// dit is een boilerplate voor een node.js webserver met alle basis die je nodig hebt om je webserver aan de praat te krijgen
// deze boilerplate is geen werkende webserver, maar een overzicht van de verschillende codefragmenten die je nodig hebt
// kopieer deze dus niet integraal, maar zoek de stukjes die je nodig hebt en pas ze aan, zodat ze werken voor jouw project

// Add info from .env file to process.env
const dotenv = require('dotenv').config()
const crypto = require('crypto')
const xss = require('xss')
const bcrypt = require('bcryptjs')

require('dotenv').config()

// Initialise Express webserver
const express = require('express')
const session = require('express-session')
const app = express()

const authRoutes = require('./routes/authRoutes')

app
    .use(express.urlencoded({ extended: true })) // middleware to parse form data from incoming HTTP request and add form fields to req.body
    .use(express.static('static'))             // Allow server to serve static content such as images, stylesheets, fonts or frontend js from the directory named static
    .use(session({
        secret: process.env.SESSION_SECRET, // vervang dit door een sterke geheime sleutel
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } // zet dit op true als je HTTPS gebruikt
    }))
    
    .set('view engine', 'ejs')                 // Set EJS to be our templating engine
    .set('views', 'views')                      // And tell it the views can be found in the directory named view

    .use('/', authRoutes)

    // Middleware om sessie-informatie beschikbaar te maken in alle templates
    .use((req, res, next) => {
        res.locals.user = req.session.user
        next()
    })

    .get('/sessionInfo', (req, res) => {
        res.json(req.session)
    })

// Use MongoDB
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
        console.log(`For uri - ${uri}`)
    })

// A sample route, replace this with your own routes
app.get('/', (req, res) => {
    res.send('Hello World!')
})

// Middleware to handle not found errors - error 404
app.use((req, res) => {
    // log error to console
    console.error('404 error at URL: ' + req.url)
    // send back a HTTP response with status code 404
    res.status(404).send('404 error at URL: ' + req.url)
})

// Middleware to handle server errors - error 500
app.use((err, req, res) => {
    // log error to console
    console.error(err.stack)
    // send back a HTTP response with status code 500
    res.status(500).send('500: server error')
})

// Start the webserver and listen for HTTP requests at specified port
app.listen(process.env.PORT, () => {
    console.log(`listening at port: http://localhost:${process.env.PORT}/`)
})