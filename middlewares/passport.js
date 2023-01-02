//Contiene la configuración del middleware de passport
//Passport local es una strategy para autenticación con un username y un password
//La strategy requiere un callback varyvy, el cual acepta las credenciales y llama al metodo done, una vez comprobado el user

const bcrypt = require('bcrypt');                           //Importamos el modulo bcrypt
const passport = require('passport');                       //importamos el modulo passport
const LocalStrategy  = require('passport-local').Strategy;  //importamos passport-local y su clase Strategy

const salt = () => bcrypt.genSaltSync(10);                  //Crea una string aleatoria que se usa al momento de encryptar
const createHash = (password) => bcrypt.hashSync(password, salt());
const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);    //Metodo para comparar passwords


//passport local strategy

//sign Up
passport.use('signup', new LocalStrategy({
    passReqToCallback: true
}, async (req, username, password, done) => {
    try {
        const newUser = {
            email: username,
            password: createHash(password)
        }

        console.log("Usuario registrado exitosamente");
        return done(null, newUser);
    }
    catch(error){
        console.log ("Error al registrar el usuario");
        return done(error);
    }
}));

// Sign in
passport.use('signin', new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.getByEmail(username);
        if (!isValidPassword(user, password)) {                     //Compara si el password corresponde al usuario
            console.log("Usuario o password no validos");
            return done(null, false);
        }
        return done(null, user);                                    //Si la contraseña es valida regresa el usuario
    }
    catch(error) {
        console.log("Error al iniciar session");
        return done(error);
    }
}))

module.exports = passport;