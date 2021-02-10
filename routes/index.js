const data = require("../data/user");
const bcrypt = require("bcrypt");
const pass = require('passport')
const session = require('express-session');
const saltRounds = 16;
const constructorMethod = app => {


    app.get("/", async(req, res) => {
        try {


            if (req.session.userlogged == undefined || req.session.userlogged == null) {
                //console.log(req.session.userlogged)
                //console.log(req.session)
                //console.log(req.session.isAuthenticated)
                req.session.isAuthenticated = false;
                res.render("login", {});
            } else {

                req.session.isAuthenticated = true;
                res.redirect("/private");
            }
        } catch (e) {
            res.status(403).render("login", { errors: "Invalid Request", hasErrors: true });
        }
    });

    app.use(function(req, res, next) {

        let requestLog = "[" + new Date().toUTCString() + "]: " + req.method + " " + req.originalUrl;
        //console.log(req.isAuthenticated)
        //console.log(req.session.isAuthenticated)
        if (!req.session.isAuthenticated) {

            requestLog = requestLog + " (Not Authenticated)";
        } else
            requestLog = requestLog + " (Authenticated)";
        console.log(requestLog);
        next();
    });




    app.post("/login", async(req, res) => {
        //console.log(req.body)
        //console.log(req.body.username)
        //console.log(req.body.password)
        if (!req.body) {

            res.status(403).render("login"), { errors: "Invalid Request", hasErrors: true };
        }
        if (!req.body.username) {
            res.status(403).render("login"), { errors: "Invalid Request", hasErrors: true };
        }
        if (!req.body.password) {
            res.status(403).render("login"), { errors: "Invalid Request", hasErrors: true };
        }
        try {
            let user = { userName: req.body.username, password: req.body.password }
            console.log("UserName: " + user.userName);
            console.log("Password: " + user.password);

            let result = await data.getdata(user.userName);
            //console.log(result)
            if (result === undefined || result === null || result.length == 0) {
                res.status(401).render("login", { errors: "Provide a valid username and/or password.", hasErrors: true });
            } else {
                const d = bcrypt.hashSync(user.password, saltRounds)
                    //console.log(bcrypt.hashSync(user.password, saltRounds))
                    //console.log(result.hashedPassword)
                let hashed = await bcrypt.compare(user.password, result.hashedPassword);
                //let hashed = await bcrypt.compare(user.password, d);
                //console.log(hashed)
                if (hashed) {
                    req.session.isAuthenticated = true;
                    req.session.userlogged = result;
                    res.redirect("/private");
                } else
                    res.status(401).render("login", { errors: "Provide a valid username and/or password.", hasErrors: true });
            }
        } catch (e) {
            res.status(403).render("login", { errors: "Invalid Request", hasErrors: true });
        }
    });


    app.get("/logout", async(req, res) => {
        //console.log(req.session.userlogged)
        //console.log(req.session.isAuthenticated)
        try {
            res.clearCookie("AuthCookie");
            req.session.userlogged = null;
            req.session.isAuthenticated = false;
            res.render("logout", { ErrorMessage: "You have been logged out successfully" });
        } catch (e) {
            res.status(403).render("login", { errors: "Invalid Request", hasErrors: true });
        }

        // app.get("/logout", (req, res) => {
        //   //expire the AuthCookie and inform the user that they have been logged out
        //   res.clearCookie('AuthCookie');

        //   //It will provide a URL to the / route
        //   res.redirect('/login');
        //   console.log("you are logged out");
    });


    const logRequest = async(req, res, next) => {
        if (req.session.userlogged == null || req.session.userlogged == undefined) {

            res.status(403).render("login", {});
        } else {

            next();
        }
    };

    app.get("/private", logRequest, async(req, res) => {


        try {
            res.render("private", { Matter: req.session.userlogged });
        } catch (e) {
            res.status(403).render("login", { errors: "Invalid Request", hasErrors: true });
        }
    });

    app.get("*", async(req, res) => {

        res.redirect("/");
    });
};
module.exports = constructorMethod;