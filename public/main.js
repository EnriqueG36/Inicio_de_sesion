//MAIN:JS CONTIENE LA LOGICA DEL CLIENTE

//Instanciar la conexion del cliente hacia el servidor socket
const socket = io();        //Socket server connection

/*A continuacion, el metodo socket.on estará escuchando en el lado del cliente por cualquier evento llamado 'messages' y
recibirá como argumento de su callback, un parametro data, que es el argumento que estamos pasando en el lado del servidor 
(como el arreglo de mensajes por ejemplo)
*/


//---------------------------------
//Llama a la plantilla de handlebars con fetch() y le pasa el arreglo de productos
async function renderProducts(products){
    
    console.log(products);                  
    
    const fetchHBS = await fetch("plantillaProductos.hbs");
    const textHBS = await fetchHBS.text();
    const template = Handlebars.compile(textHBS);
    const html2 = template({products});

    document.getElementById("plantillaProductos").innerHTML = html2;
}

const hoy = new Date();                                                 //Nueva instancia de la clase Date

socket.on('messages', (data) => {

    const chat = document.getElementById("mensajeria");                 //chat será igual al elemento con id "mensajeria"

    const html = data.map((elem) => {                                   //itera por el arreglo de mensajes y separa cada elemento 
        return(`<div><p style="color:brown;">
            <strong style="color:blue;">${elem.author}: </strong>${elem.messageDate}
            <em style="color:green;">${elem.text}</em></p></div>`)
    }).join(" ");
    

    chat.innerHTML = html;
    //renderProducts();

});

socket.on('productos', renderProducts);

//Envia los mensajes que entren desde el formulario, hacia el servidor con el metodo emit
function addMessage(e) {

    const momento = hoy.toLocaleString();                               //Convertimos fecha y hora a formato string, para añadirla al los objetos en el arreglo de mensajes
    
    const mensaje = {
        author: document.getElementById('username').value,
        messageDate: momento,
        text: document.getElementById('texto').value
    };
    if ((mensaje.author != "") && (mensaje.text != ""))                 //Validamos si se introdujo el emal y algun mensaje, si no, no es posible enviar nada por el chat
    socket.emit('new-message', mensaje);
    
    return false;
}

function addProducto() {

    const nuevoProducto = {
        title: document.getElementById('title').value,
        price: document.getElementById('price').value,
        thumbnail: document.getElementById('thumbnail').value
    };
    if((nuevoProducto.title != "") && (nuevoProducto.price != "") && (nuevoProducto.thumbnail != ""))
    socket.emit('cambio-tabla-productos', nuevoProducto);

    return false;
}

//Monstrar el nombre del Usuario 
async function compilarPlantillaUsuario(usuario) {

const fetchHBS = await fetch("plantillaNombreUsuario.hbs");
const textHBS = await fetchHBS.text();
const plantillaDelUsuario = Handlebars.compile(textHBS);
const nombreUsuario = plantillaDelUsuario({usuario});
document.getElementById("nombreUsuario").innerHTML = nombreUsuario;
}

socket.on ('mostrarNombreSession', compilarPlantillaUsuario);