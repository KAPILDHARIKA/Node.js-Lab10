const express = require('express');
const exphbs = require('express-handlebars')
const session = require('express-session')
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const configRoutes = require("./routes");


const app = express();

app.engine('handlebars', exphbs({ defaultLayout: 'main' }));
app.set('view engine', 'handlebars');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(cookieParser());
app.use(session({
    name: 'AuthCookie',
    secret: 'some secret string!',
    resave: false,
    saveUninitialized: true
}))
const static = express.static(__dirname + '/public');
app.use('/public', static);
configRoutes(app);


app.listen(3000, () => {
    console.log("We've now got a server!");
    console.log("Your routes will be running on http://localhost:3000");
});