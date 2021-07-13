const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require ('jsonwebtoken')

const JWT_SECRET = 'sfdz52dsfa5632ds4564356$%^&cdshbcjafksjnvsj'

mongoose.connect('mongodb://localhost:27017/login-app-db',{
    useNewUrlParser:true,
    useUnifiedTopology:true,
    useCreateIndex:true
})

const app = express()
app.use('/',express.static(path.join(__dirname,'static')))
app.use(bodyParser.json())

app.post('/api/change-password', async (req, res) => {
    const { token, newpassword : password } = req.body
    
    if(!password || typeof password!== 'string' ){
        return res.json({
            status:'error',
             error:'Invalid password' 
        })
    }

    if(password.length < 5) {
        return res.json({status:'error', error:'Password too samll. Should be atleast 6 characters' })
    }

    try{
        const user = jwt.verify(token, JWT_SECRET) 
        
        const _id=user.id 

        const password = await bcrypt.hash(password, 10)
        
        await User.updateOne(
            { _id},
            {
                 $set:{ password }
            }
        )
        res.json({status:'ok'})
    }catch(error){
        console.log(error)
        res.json({status:'error', error:';))' })
    }
    
   
})

app.post('/api/login',async (req, res) => {
    const{ username,password} = req.body
    const user = await User.findOne({ username}).lean()

    if(!user){
        return res.json({ status:'error', error: 'Inavlid username/password'})
    }

    if(await bcrypt.compare(password, user.password)){
        // the username password combination successful

        const token = jwt.sign(
        {
            id: user._id,
            username: user.username
        },
         JWT_SECRET
    )

        return res.json({ status:'ok', data:token})
    }

    res.json({status:'error', error:'Invalid username/password'})
})

app.post('/api/register',async(req,res) => {
    let {username,email, password, contact} = req.body

    if(!username || typeof username!== 'string' ){
        return res.json({status:'error', error:'Invalid username' })
    }

    if(!password || typeof password!== 'string' ){
        return res.json({
            status:'error',
             error:'Invalid password' 
        })
    }

    if(password.length < 5) {
        return res.json({status:'error', error:'Password too samll. Should be atleast 6 characters' })
    }

    password = await bcrypt.hash(password,10) 
     
 
    try{
        const response = await User.create({
            username,
            password,
            email,
            contact
        })
        console.log('User created successfully',response)
    }catch(error){
        if (error.code === 11000) {
            //duplicate key
            return res.json({ status : 'error', error:'Username already in use'})
        }
        throw error
        
    }

    res.json({ status:'ok'})
})

app.listen(9999,() => {
    console.log('Server up at 9999')
})