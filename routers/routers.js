//Intanciación de nuestro Router

const express = require('express');                                     //Importamos el modulo express
const productosRoutes = require ('./productos/productos.routes');       //Importamos nuestro js del recurso Productos

const router = express.Router();                                        //instanciamos nuestro Router

router.use('/productos', productosRoutes);

module.exports = router;                                                //Exportamos nuestro router