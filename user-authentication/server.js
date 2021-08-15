const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

app.use(express.json())

const users = []

app.get('/users', (req, res) => {
    res.json(users)
})

app.post('/users', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        console.log(hashedPassword)
        const user =  {
            'name' : req.body.name,
            'password' : hashedPassword
        }
        users.push(user)
        res.sendStatus(201)
    } catch {
        res.sendStatus(500)
    }
})

app.post('/users/login', async (req, res) => {
    const user = users.find(user => user.name === req.body.name)
    if (user == null) {
        return res.sendStatus(400)
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            res.send('Success')
        } else {
            res.send('Failure')
        }
    } catch {
        res.sendStatus(500)
    }
})

app.listen(3000)