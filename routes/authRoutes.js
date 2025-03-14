const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const xss = require('xss')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
// Construct URL used to connect to database from info in the .env file
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_NAME}?retryWrites=true&w=majority`
// Create a MongoClient
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
})

// Try to open a database connection
client.connect()
    .then(() => {
        console.log('Database connection established')
    })
    .catch((err) => {
        console.log(`Database connection error - ${err}`)
    })

router
    .get('/login', (req, res) => {
        res.render('pages/login.ejs', { title: 'Login' })
    })

    .post('/loginAccount', async (req, res) => {
        try {
            const dataBase = client.db(process.env.DB_NAME)
            const collection = dataBase.collection(process.env.DB_COLLECTION)

            const username = xss(req.body.username)
            const password = xss(req.body.password)

            const user = await collection.findOne({
                username: username
            })

            if (user && await bcrypt.compare(password, user.password)) {
                req.session.user = {
                    _id: user._id,
                    username: user.username,
                    email: user.email,
                    password: user.password,
                  }
                res.redirect('/home')
            } else {
                return res.render('pages/login.ejs', { title: 'Login', error: 'Invalid username or password'})
            }
        } catch (err) {
            console.error(err)
            return res.status(500).render('pages/login.ejs', { title: 'Login', error: 'An error occurred during login'})
        }
    })


    .get('/register', (req, res) => {
        res.render('pages/register.ejs', { title: 'Register' })
    })

    .post('/registerAccount', async (req, res) => {
        try {
            const dataBase = client.db(process.env.DB_NAME)
            const collection = dataBase.collection(process.env.DB_COLLECTION)

            const email = xss(req.body.email)
            const username = xss(req.body.username)
            const password = xss(req.body.password)

            const duplicateUser = await collection.findOne({ username: username })
            if (duplicateUser) {
                console.log('Username already taken')
                return res.render('pages/register.ejs', { title: "Register", error: 'Username already taken', username: null })
            }

            const duplicateEmail = await collection.findOne({ email: email });
            if (duplicateEmail) {
                console.log('Email already taken')
                return res.render('pages/register.ejs', { title: "Register", error: 'Email already taken', email: null })
            }

            console.log('Hashing password')
            const hashedPassword = await bcrypt.hash(password, 10)

            console.log('Inserting new user')
            const result = await collection.insertOne({
                email: email,
                username: username,
                password: hashedPassword,
            })
            req.session.user = {
                _id: result.insertedId,
                username: username,
                email: email,
                password: hashedPassword
              }
            res.redirect('/login')
        } catch (err) {
            console.error(err)
            return res.status(500).render('pages/register.ejs', { title: 'Register', error: 'An error occurred during registration' })
        }
    })

module.exports = router