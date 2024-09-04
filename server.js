const express=require('express')
const {open}=require('sqlite')
const sqlite3=require('sqlite3')
const cors=require('cors')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const path=require('path')

const app=express()
const dbPath=path.join(__dirname,"todoUsers.db")

app.use(express.json())
app.use(cors({
    origin:'http://localhost:3000',
    methods:['POST','GET'],
    allowedHeaders:['Content-Type','Authorization']
}))

let db=null
const initiateAndStartDatabseServer=async()=>{
    try{
       db=await open({
        filename:dbPath,
        driver:sqlite3.Database
       })
       app.listen(3000,()=>{
        console.log('Backend Server is Running at http://localhost:3000/')
       })
    }catch (e){
        console.log(`DB Error ${e.message}`)
        process.exit(1)
    }
}

initiateAndStartDatabseServer()

app.post('/signup',async(req,res)=>{
   try{
    const {username,email,password}=req.body
    const hashedPassword=await bcrypt.hash(password,10)
    const insertQuery=`insert into users(username,email,password) values (?,?,?);`
    await db.run(insertQuery,[username,email,hashedPassword])
    res.status(201).json({message:'inserted data successfully'})
   }catch (error){
    res.status(500).json({error:`failed to insert the data,${error.message}`})
   }
})


app.post('/login',async(req,res)=>{
    try{
        const {username,password}=req.body
        const selectUserQuery=`select * from users where username=?;`
        const dbUser=await db.get(selectUserQuery,[username])
        if(dbUser===undefined){
            res.status(400).json({message:'invalid User or password'})
        }else{
            const isMatchedPassword=await bcrypt.compare(password,dbUser.password)
            if(isMatchedPassword===true){
               const payload={
                username:username
               }
               const jwtToken=jwt.sign(payload,'secret_token')
               res.status(200).json({jwtToken})
            }else{
                res.status(400).json({message:'invalid User or password'})
            }
        }
    }catch (e){
        res.status(500).json({ error: `Error processing request: ${e.message}` });
    }
})