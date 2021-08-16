require('dotenv').config()

const express = require('express')
const app = express()

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

app.use(express.json())

const posts = [
    {
        username : 'pradeepmsuresh',
        title : 'Post 1'
    },
    {
        username : 'Jim',
        title : 'Post2'
    }
]

const users = []

const refreshTokens = []

const authenticate = async function (requestPassword, dbPassword) {
    try {
        let authenticated = await bcrypt.compare(requestPassword, dbPassword)
        if (authenticated){
            return true
        } else {
            return false
        }
    } catch {
        throw Error('Error in authentication')
    }
}

const authenticateToken = function (req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) {
        return res.sendStatus(401)
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403)
        }
            req.username = user
        next()
    })
} 

const generateAccessToken = function(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '50s'})
}


app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.username.name))
})


app.post('/user', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const user = {
            username : req.body.username,
            password : hashedPassword
        }
        users.push(user)
        res.status(201).send('Created')
    } catch {
        res.status(500).send('Failure')
    }
})

app.post('/user/login', async (req, res) => {
    const user = users.find(user => user.username === req.body.username)
    if (user == undefined){
        return res.status(400).send('User Not found')
    }
    try {
        if (await authenticate(req.body.password, user.password)) {
            const user = {name : req.body.username}
            const accessToken = generateAccessToken(user)
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
            refreshTokens.push(refreshToken)
            res.json({accessToken : accessToken, refreshToken: refreshToken})
        } else {
            res.status(400).send('Not Found')
        }
    } catch(err) {

        res.status(500).send(err.name + ': ' + err.message)
    }  

})

app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(404)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({name : user.name})
        res.json({accessToken : accessToken})
    })
})
app.listen(3000)