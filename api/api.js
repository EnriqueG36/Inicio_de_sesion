//const { productos } = require('../data/productos');

//Clase API para el manejo de objetos producto
//require('../data/productos');                      // Importamos el arreglo de productos

class API {
    constructor() {
        this.productos = [
            {id: 1, title: 'Teclado', price: 2500, thumbnail: 'http:/ algo teclado'},
            {id: 2, title: 'Mouse', price: 350, thumbnail: 'http:/ algo mouse'},
            {id: 3, title: 'Monitor', price: 7000, thumbnail: 'http:/ algo monitor'}
        ];
    }

    //Metodo para obtener todo el arreglo
    getAll(){
        return this.productos;
    }

    //Busca un producto en el arreglo por el id proporcionado
    getById(idABuscar){
        
        const productoEncontrado = this.productos.find((product) => product.id === +(idABuscar));   //Busca si el id recibido existe en el arreglo
        if (productoEncontrado){
            return productoEncontrado;                      //Regresa el objeto encontrado
        }
        else {
            return ({error: 'Producto no encontrado'});     //Si el Id no se encuentra, regresa este mensaje
        }
       
    }

    addNew(body){

        const {title, price, thumbnail} = body;
        if (!title || !price || !thumbnail) {
            return ({error: "Formato del cuerpo incorrecto"})
        }
        const nuevoProducto = {
            id: this.productos.length + 1,
            title,
            price,
            thumbnail
        };
        this.productos.push(nuevoProducto);
        return (nuevoProducto);

        }
    

    updateById(id, body){

        //Buscamos si el objeto a actualizar existe en el arreglo productos y obtenemos el indice
        const indexProductos = this.productos.findIndex((product) => product.id === +(id));
        if(indexProductos < 0){
            return ({error: `El Id ${id} no se encuentra, no se puede actualizar`});
        }

         //Tomamos el id del objeto encontrado
        const idActualizar = this.productos[indexProductos].id;        


        const {title, price, thumbnail} = body;
        if (!title || !price || !thumbnail) {
            return ({error: "Formato del cuerpo incorrecto, no se puede actualizar"})
        }

        //Creamos un nuevo objeto a partir del body recibido, y del id del objeto producto encontrado
        const nuevoProducto = {
            id: idActualizar,
            title,
            price,
            thumbnail
        };

        //Reemplazamos el producto del arreglo con el nuevo objeto
        this.productos[indexProductos] = nuevoProducto;
        console.log(nuevoProducto)

        return this.productos;

    }

    deleteById(idAEliminar){

        const indexProductos = this.productos.findIndex((product) => product.id === +(idAEliminar));
        if(indexProductos < 0){
            return ({error: `El Id ${idAEliminar} no se encuentra`});
        }

        this.productos.splice(indexProductos, 1);

        console.log (`Id eliminado ${idAEliminar}`);
        return this.productos;

    }
    
}

module.exports = API;