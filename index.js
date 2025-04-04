// IMPORTACIONES
import express from 'express';
import pg from 'pg';
import bodyParser from "body-parser"
import bcrypt from 'bcrypt'
import session from 'express-session';
import passport from "passport";
import { Strategy } from 'passport-local';
import env from "dotenv"

// INICIALIZACION
env.config()
const app=express();
const port=3000;
const saltRounds=10;
app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static('public'));
const db=new pg.Client({
    user:process.env.DB_USER,
    host:process.env.DB_HOST,
    database:process.env.DB_DATABASE,
    password:process.env.DB_PASSWORD,
    port:process.env.DB_PORT
});
db.connect();
app.use(
    session({
        secret:process.env.SESSION_SECRET,
        resave:false,
        saveUninitialized:true,
        cookie:{
            maxAge:1000*60*60
        }
    })
)
app.use(passport.initialize());
app.use(passport.session());
app.use((req,res,next)=>{
    console.log(`Usuario actual: ${req.user}`);
    
    res.locals.msg=null
    next();
})


// GET ROUTES
app.get('/',async(req,res)=>{
    res.redirect('/inicioSesion')
});
app.get('/inicioSesion',(req,res)=>{
    res.render('inicio.ejs')
})
app.get('/registrar',(req,res)=>{
    const errorMsg=req.session.msg
    req.session.msg=null
    res.render('registro.ejs',{
        msg:errorMsg
    })
})
app.get('/home',(req,res)=>{{
    if(req.isAuthenticated()){
        res.render('home.ejs')
    } else {
        res.redirect('/')
    }
}})
app.get('/logout',(req,res)=>{
    req.logout(function (err){
        if (err){
            console.log(err);
            return next(err)
        }  
        req.session.user=null
        res.redirect('/')
    })
})


// POST ROUTES
app.post('/registrar',async(req,res)=>{
    const usuario=req.body.user
    const contra=req.body.contra
    const confirmContra=req.body.confirmContra
    const result=await db.query("SELECT * FROM estudiantes WHERE usuario=($1)",[
        usuario
    ])
    if(result.rows.length>0){
        req.session.msg="Usuario ya existente"
        res.redirect("/registrar")
    } else {
        if(contra===confirmContra){
            try {
                bcrypt.hash(contra,saltRounds,async(err,hash)=>{
                    if(err){
                        console.log(`Error hashing ${err}`);
                    } else {
                        const result=await db.query('INSERT INTO estudiantes (usuario,contraseña) VALUES ($1,$2) RETURNING *',[
                          usuario,hash  
                        ])
                        const user=result.rows[0]
                        req.login(user,(err)=>{
                            console.log(err);
                            res.redirect('/home')
                        })
                    }
                })
            } catch (error) {
                console.log(error);
            }
        } else {
            req.session.msg="Contraseñas no coinciden";
            res.redirect('/registrar')
        }
    }
    
})
app.post('/inicioSesion',passport.authenticate('local',{
    successRedirect:'/home',
    failureRedirect:'/'
}))

// ESTRATEGIAS PASSPORT
passport.use(
    "local",
    new Strategy(async function verify(user,contra,cb){
        try {
            const result= await db.query('SELECT * FROM estudiantes WHERE usuario=$1',[
                user
            ])
            if(result.rows.length>0){
                const usuario=result.rows[0]
                const hashedPassword=usuario.contraseña
                bcrypt.compare(contra,hashedPassword,(err,valid)=>{
                    if(err){
                        console.log(`Error comparing passwords: ${err}`);
                        return cb(err)  
                    } else {
                        if(valid){
                            return cb(null,usuario)
                        } else {
                            return cb(null,false)
                        }
                    }
                })
            } else {
                return cb(null,false)
            }
        } catch (err) {
            console.log(err);
            
        }
    })
)


  passport.serializeUser((user, cb) => {
    cb(null, user);
  });
  
  passport.deserializeUser((user, cb) => {
    cb(null, user);
  });


app.listen(port,()=>{
    console.log(`server running in port ${port}`);
    
})