//Desafio Inicio de sesion
//INDEX:JS CONTIENE LA LOGICA DEL SEVIDOR

const express = require('express');                 //Importamos el modulo express
const {Server: HttpServer} = require('http');       //Importamos la clase Server del modulo nativo de nodejs "http" pero le cambiaremos el nombre 
                                                    //por HttpServer para evitar confusiones al trabajar
const {Server: SocketServer} = require('socket.io'); //Importamos el modulo socket.io y le cambiamos el nommbre 
const path = require('path');
const {engine} = require('express-handlebars');
const apiRoutes = require('./routers/routers');
const fs = require("fs");                           //Importamos el modulo file System
const session = require('express-session');         //Importamos express-session
const  MongoStore = require('connect-mongo');       //Requerimos el modulo connect-mongo
const passport = require('./middlewares/passport.js');  //Importamos el middleware passport

//A continuacion la configuración básica de un servidor http con socket en conjunto
const PORT = process.env.PORT || 8080;              //Configuramos el puerto por la variable de entorno O por el 8080
const app = express();                              //Instanciamos el modulo express
const httpServer = new HttpServer(app);             //instanciamos el servidor http, pasando por parametro la instancia de express
const io = new SocketServer(httpServer);            //intanciamos el servidor socket pasando como parametro la intancia http

//Objeto de configuracion Bases de datos
const dbConfig = require('./db/config.js')         //Importamos nuestro objeto de configuracion Knex
                           
//Configuración del motor de plantilla para el uso de HANDLEBARS
app.engine('hbs', engine({
    extname: 'hbs',
    
    layoutsDir: path.resolve(__dirname, './views/layouts'),
    partialsDir: path.resolve(__dirname, './views/partials')
}));

//Setteando la carpeta de plantillas y extension de las mismas
app.set('views','./views');                         //Indicamos a express la ruta de nuestra plantilla
app.set('view engine', 'hbs');                      //Indicamos a express el motor de plantillas a usar

//Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static("./public"));                //Archivos estaticos
app.use(session({
    secret: 'firma-secreta-desafio-LogIn',          //Firma para la cookie generada por session
    resave: false,                                  //Autoguarda cambios en la session
    saveUninitialized: false,
    store: MongoStore.create({
       mongoUrl: 'mongodb+srv://enrique:dbmongo@clustercoder.ijswitn.mongodb.net/DesafioInicioSesion?retryWrites=true&w=majority',
    }),
    cookie: {
        maxAge: 600000                              //Duracion de la session en mongo atlas 10 min
    }
}))
app.use(passport.initialize());                     //Aquí implementamos el passport
app.use(passport.session());

// Rutas desafio Inicio de sesion------------------------------------------------------------------------------------------------------

//Routes
app.use('/api', apiRoutes);                      //Ruta a routers.js con prefijo /api

/*app.get('/', (req, res) => {
    res.send("pantalla de inicio");
});*/

let nombreDelUser;

//En esta ruta se setteará la session
/*app.post('/login', (req, res) => {
    const { user } = req.body;                  //tomamos el nombre del usuario del body de la peticion    
    req.session.user = user;                    //Setteamos el nombre del usuario de la session
    req.session.save((err) => {                 //Guardamos la session
      if (err) {
        console.log("Session error => ", err);
        return res.redirect('/error');
      }
        return res.redirect('/index2');      
    })
  });
  */

 app.post('/registro', passport.authenticate('signup', {failureRedirect: '/signup-error'}), redirect('/index2'));

//Aquí debe de ir la logica para ver si la session está activa
app.get('/index2', (req, res) => {
    const user = req.session.user;                                  //Requerimos el nombre del usuario de la session
    nombreDelUser = user;
    if (user)                                                       //Si el usuario se encuntra a la session, enviaremos el archivo index2.html
    res.status(200).sendFile(__dirname+'/public/index2.html');
    else                                                            //De otra forma se redirige a la pantalla de loggeo
    return res.redirect('/');
});

app.get('/registro', (req, res) => {
    return res.sendFile(__dirname+'/public/registro.html');
}); 

app.get('/error', (req, res) => {
    res.send("Pantalla de error, porque hubo un error");
});

app.get('/logout', (req,res) => {

    const user = req.session.user;    
    console.log(user);

    if (user){                                                               //Validamos si hay una session de usuario activa           
    
    req.session.destroy (err => {
        if (!err) {
            res.render('index', {layout: 'logout', user});                  //Respondemos la peticion con la plantilla 
            //setInterval(res.redirect('/'), 2000); 
        }
        else{
            res.send("Ocurrio un error");
        }     
   })}
    else                                                                    //De otra forma se redirige a la pantalla de loggeo
    return res.redirect('/');
});

//socket y demás-------------------------------------------------------------------------------------------------------------------


//clases importadas
const ApiProductos = require('./api/apiProductos.js');          //Importamos la clase ApiProductos
const apiProductos = new ApiProductos('tablaproductos');        //Nueva instancia de la clase ApiProductos, recibe el nombre de la tabla en la base de datos mariaDB
const ApiChat = require('./api/apiMensajesChatDB.js');          //Importamos la clase ApiChat
const { Store } = require('express-session');
//const passport = require('passport');
const apiChat = new ApiChat(dbConfig.sqlite3, 'tablaChat')       //Nueva instancia de la clase ApiChat, recibe la configruacion de sqlite y el nombre de la tabla en la base de datos



//Listen
httpServer.listen(PORT, ()=> {
    console.log("Server is up and running on port ", PORT);
})

//Eventos socket

// El metodo on, escuchara por el evento 'connection'
io.on('connection', async (socket)=> {
    
    console.log("New client connection! (nuevo cliente conectado)");            //Muestra mensaje en la consola cuando se conecta un nuevo cliente
    console.log(socket.id);                                                     //Muestra por consola el id del nuevo cliente conectado.
    //console.log(messages);
     
    //socket.emit('messages', messages);                                          
    socket.emit('messages', await apiChat.getAll());                                             //Emite un evento llamado messages, manda el resultado de la clase apiChat.getAll para obtener todo el historial de chat
    socket.emit('productos', await apiProductos.getAll());                                       //Emite un evento llamado productos, que manda como parametro la lista de productos
   
    
    socket.emit('mostrarNombreSession', nombreDelUser);                                         //emite el nombre de suario de la session


    //Escucha por los mensajes emitido por el lado del cliente con el metodo on
    socket.on('new-message',data => {

        //messages.push(data);
        //io.sockets.emit('messages', messages);
        io.sockets.emit('messages', apiChat.getAll());
        //fs.writeFileSync("./chat_data_log/chat_log.json", JSON.stringify(messages));        //Escribe el log del chat en un archivo
        apiChat.adNew(data);                                                                    //Guarda el nuevo mensaje de chat en la base de datos

    });

    //Escucha por los cambios en la tabla de productos      
    socket.on('cambio-tabla-productos',data => {

       
        io.sockets.emit('productos', apiProductos.getAll());        //emite a todos los sockets un evento llamado 'productos' y el metodo getAll
        apiProductos.addNew(data);                                  //Recibe data de un nuevo producto y lo pasa como argumento a la funcion addNew
    });

})