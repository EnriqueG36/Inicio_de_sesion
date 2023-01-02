//Ruta base api/productos

const express = require('express');         //Importamos el modulo express

const router = express.Router();            //instanciamos nuestro Router
const API = require('../../api/api');       //Importamos la clase API
const api = new API();                      //Nueva instancia de la clase API

//Definiremos las rutas de nuestros recursos----------------------------------------------------------------------
// Envía todo el arreglo de objetos


router.get('/', (req, res) => {
    
    //res.status(201).json(api.getAll());
    const obtenerTodos = api.getAll();                  //Obtenemos el arreglo de objetos y lo asignamos a la variable
    //console.log(obtenerTodos);                          
    res.render('index', {obtenerTodos});                //Respondemos la peticion con la plantilla 
    
});


//Devuelve un objeto según su parametro id, mediante Path params

router.get('/:id', (req, res) => {
    
    console.log (req.params);
    const {id} = req.params;

    res.status(201).json(api.getById(id));

      
});


//Recibe y agrega un producto
router.post('/', (req,res) => {
   console.log (req.body);                                          //Muestra en consola del servidor el body de la petición POST
    //res.status(201).json(api.addNew(req.body));
    api.addNew(req.body);                                           //Tomamos el cuerpo de la peticion POST y lo pasamos como parametro a el objeto de la 
                                                                    // clase API, para ser añadido al arreglo de objetos productos
    res.redirect('/');                                              //Redirige a la ruta base
});

//Actualiza un objeto producto según los params id y body
router.put('/:id', (req, res) => {
    console.log(req.params);
    console.log(req.body);

    const {id} = req.params;

    res.json(api.updateById(id, req.body));            //La funcion updateById recibe dos parametros, el Id y el Body


});

//Elimina un producto según su id
router.delete('/:id', (req, res) => {

    console.log(req.params);
    const {id} = req.params;

    res.status(201).json(api.deleteById(id))

});

//--------------------------------------------------------------------------------------------------------------
module.exports = router;                    //Exportamos nuestro Router