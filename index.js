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
        saveUninitialized:false,
        cookie:{
            maxAge:1000*60*60
        }
    })
)
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: true }))
app.use((req,res,next)=>{
    console.log(`Usuario actual: ${JSON.stringify(req.user,null,2)}`);
    
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
app.get('/home', async (req,res)=>{{
    const result=await db.query("SELECT * FROM profesores")
    const data=result.rows
    if(req.isAuthenticated()){
        const idEst=req.user['codigo_estudiante']
        const resultEst=await db.query("SELECT * FROM estudiantes WHERE codigo_estudiante=$1",[
            idEst
        ])
        const dataEst=resultEst.rows
        res.render('home.ejs',{
            data:data,
            dataEst:dataEst
            })
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
app.get('/error',(req,res)=>{
    res.render('error.ejs')
})
app.get('/profesor/:nombre',async(req,res)=>{
    const paginaAnt=req.get("Referer") || "/"
    const nombre=req.params.nombre
    const errorMsg=req.session.msg
    req.session.msg=null
    if(req.isAuthenticated()){
        const idEst=req.user['codigo_estudiante']
        const result=await db.query("SELECT * FROM profesores WHERE nombre=$1",[
            nombre
        ])
        const resultEst=await db.query("SELECT * FROM estudiantes WHERE codigo_estudiante=$1",[
            idEst
        ])
        const dataEst=resultEst.rows
        const data=result.rows
        const nota= await db.query('SELECT p.id,p.nombre,ROUND(AVG(c.calificacion),1) AS promedio_calificacion FROM profesores p LEFT JOIN calificaciones c ON p.id = c.id_profesor WHERE p.id=$1 GROUP BY p.id, p.nombre',
            [data[0].id]
        )
        const calificacion=nota.rows
        console.log(calificacion[0].promedio_calificacion);
        
        res.render("profesor.ejs",{
            data:data,
            dataEst:dataEst,
            nota:calificacion[0].promedio_calificacion,
            errorMsg:errorMsg,
            paginaAnt:paginaAnt
        })
    } else {
        res.redirect('/')
    }
 
})


// POST ROUTES
app.post('/registrar',async(req,res)=>{
    const usuario=req.body.user
    const name=req.body.name
    const contra=req.body.contra
    const confirmContra=req.body.confirmContra
    const result=await db.query("SELECT * FROM estudiantes WHERE codigo_estudiante=$1",[
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
                        console.log(usuario);
                        
                        const result=await db.query('INSERT INTO estudiantes (codigo_estudiante,nombre,contraseña) VALUES ($1,$2,$3) RETURNING *',[
                          usuario,name,hash  
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
app.post('/calificar',async (req,res)=>{
    const paginaAnt=req.get("Referer") || "/"
    const idEst=req.body.idEstudiante
    const idProf=req.body.idProf
    const calificaion=req.body.nota
    const coment=req.body.coment
    try {
        await db.query('INSERT INTO calificaciones (id_estudiante,id_profesor,calificacion,comentario) VALUES ($1,$2,$3,$4)',[
            idEst,idProf,calificaion,coment
        ])
        res.redirect(paginaAnt)
    } catch (error) {
        req.session.msg="Error al enviar calificacion"
        console.log(error);
        res.redirect('/error')
    }
})

// ESTRATEGIAS PASSPORT
passport.use(
    "local",
    new Strategy({usernameField:'user',passwordField:'contra'},async function verify(user,contra,cb){
        try {
            const result= await db.query('SELECT * FROM estudiantes WHERE codigo_estudiante=$1',[
                user
            ])
            if(result.rows.length === 0){
                return cb(null,false)
            }
                const usuario=result.rows[0]
                const hashedPassword=usuario.contraseña
                const valid= await bcrypt.compare(contra,hashedPassword)
                if(valid){
                    return cb(null,usuario)
                } else {
                    return cb(null,false)
                }
        } catch (err) {
            console.log(err);
            return cb(err)
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