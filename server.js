const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: "supersecretkey", resave: false, saveUninitialized: true }));

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Multer for images
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if(["image/png","image/jpeg","image/jpg","image/gif"].includes(file.mimetype)) cb(null,true);
    else cb(new Error("Only images allowed"));
  }
});

// Database
const db = new sqlite3.Database("data.db");

// Create tables if they don't exist, and ensure timestamp exists
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    isAdmin INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0
  )`);

  // Posts table
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    username TEXT,
    image TEXT
  )`, function() {
    db.all("PRAGMA table_info(posts)", [], (err, cols) => {
      if(err) console.error(err);
      const hasTimestamp = cols.some(c => c.name === "timestamp");
      if(!hasTimestamp){
        db.run("ALTER TABLE posts ADD COLUMN timestamp INTEGER DEFAULT 0");
      }
    });
  });

  // Comments table
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    postId INTEGER,
    username TEXT,
    text TEXT,
    timestamp INTEGER DEFAULT 0
  )`);
});

// ---- Helper functions ----
function sanitize(text){
  return text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function checkLogged(req,res,next){
  if(req.session.user && !req.session.banned) next();
  else res.json({logged:false,success:false,message:"Not logged in or banned"});
}

// ---- Auth ----
app.post("/register",(req,res)=>{
  const {username,password} = req.body;
  if(!username || !password) return res.json({success:false,message:"Enter username/password"});
  bcrypt.hash(password,10,(err,hash)=>{
    db.run("INSERT INTO users(username,password) VALUES(?,?)",[username,hash],function(e){
      if(e) return res.json({success:false,message:"Username taken"});
      res.json({success:true});
    });
  });
});

app.post("/login",(req,res)=>{
  const {username,password} = req.body;
  db.get("SELECT * FROM users WHERE username=?",[username],(err,row)=>{
    if(!row) return res.json({success:false,message:"No such user"});
    if(row.banned) return res.json({success:false,message:"You are banned"});
    bcrypt.compare(password,row.password,(e,same)=>{
      if(same){
        req.session.user = row.username;
        req.session.isAdmin = row.isAdmin==1;
        req.session.lastPost = 0;
        req.session.lastComment = 0;
        req.session.banned = row.banned==1;
        res.json({success:true});
      } else res.json({success:false,message:"Wrong password"});
    });
  });
});

app.get("/logout",(req,res)=>{
  req.session.destroy();
  res.json({success:true});
});

app.get("/profile",(req,res)=>{
  if(req.session.user) res.json({logged:true,user:req.session.user,isAdmin:req.session.isAdmin});
  else res.json({logged:false});
});

// ---- Post routes ----
app.post("/upload", checkLogged, upload.single("image"), (req,res)=>{
  try{
    const now = Date.now();
    if(now - req.session.lastPost < 10000) return res.json({success:false,message:"Wait 10 seconds before posting again"});
    req.session.lastPost = now;

    if(!req.file) return res.json({success:false,message:"No file uploaded"});
    const filename = "/uploads/"+req.file.filename;

    db.run("INSERT INTO posts(username,image,timestamp) VALUES(?,?,?)",[req.session.user,filename,Date.now()],function(e){
      if(e){
        console.error("DB insert error:", e);
        return res.json({success:false,message:"DB error: "+e.message});
      }
      res.json({success:true});
    });
  } catch(err){
    console.error("Upload error:", err);
    res.json({success:false,message:"Upload error: "+err.message});
  }
});

app.get("/posts", checkLogged, (req,res)=>{
  db.all("SELECT * FROM posts ORDER BY timestamp DESC",(err,rows)=>{
    res.json(rows);
  });
});

app.post("/delete/:id", checkLogged, (req,res)=>{
  const postId = req.params.id;
  db.get("SELECT * FROM posts WHERE id=?",[postId],(err,row)=>{
    if(!row) return res.json({success:false,message:"No such post"});
    if(row.username!==req.session.user && !req.session.isAdmin) return res.json({success:false,message:"Not allowed"});
    db.run("DELETE FROM posts WHERE id=?",[postId]);
    if(row.image) fs.unlink(path.join(__dirname,row.image),()=>{});
    db.run("DELETE FROM comments WHERE postId=?",[postId]);
    res.json({success:true});
  });
});

// ---- Comment routes ----
app.post("/comment/:id", checkLogged, (req,res)=>{
  const postId = req.params.id;
  const text = sanitize(req.body.text||"").trim();
  if(!text) return res.json({success:false,message:"Empty comment"});

  const now = Date.now();
  if(now - req.session.lastComment < 10000) return res.json({success:false,message:"Wait 10 seconds before commenting"});
  req.session.lastComment = now;

  db.run("INSERT INTO comments(postId,username,text,timestamp) VALUES(?,?,?,?)",[postId,req.session.user,text,Date.now()],function(e){
    if(e) return res.json({success:false,message:"DB error"});
    res.json({success:true});
  });
});

app.get("/comments/:id", checkLogged, (req,res)=>{
  const postId = req.params.id;
  db.all("SELECT * FROM comments WHERE postId=? ORDER BY timestamp ASC",[postId],(err,rows)=>{
    res.json(rows);
  });
});

app.post("/delete-comment/:id", checkLogged, (req,res)=>{
  const commentId = req.params.id;
  db.get("SELECT * FROM comments WHERE id=?",[commentId],(err,row)=>{
    if(!row) return res.json({success:false,message:"No such comment"});
    if(row.username!==req.session.user && !req.session.isAdmin) return res.json({success:false,message:"Not allowed"});
    db.run("DELETE FROM comments WHERE id=?",[commentId]);
    res.json({success:true});
  });
});

// ---- Admin ban ----
app.post("/ban/:username", checkLogged, (req,res)=>{
  if(!req.session.isAdmin) return res.json({success:false,message:"Not allowed"});
  const username = req.params.username;
  db.run("UPDATE users SET banned=1 WHERE username=?",[username],function(e){
    if(e) return res.json({success:false,message:"DB error"});
    res.json({success:true,message:"User banned"});
  });
});

// ---- Start server ----
app.listen(3000,()=>console.log("Server running on http://localhost:3000"));