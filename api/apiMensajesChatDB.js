//api para escribir los mensajes de chat en la base de datos de sqlite


class Apichat {
    constructor (configuracion, nombreTabla) {
        this.knex = require("knex")(configuracion);
        this.nombreTabla = nombreTabla;
    }

    //Metodo para obtener los mensajes almacenados en la db
    async getAll(){
        try{
            const chat = await this.knex.from(this.nombreTabla).select('*');            //Lee todos los registros de la tabla en sqlite
            return chat;                                                                //Regresa el arreglo de objetos con los mensajes y demás información
        }
        catch(error)
        {
            console.log(error)
        }
    }

    //Metodo para escribir los nuevos mensajes que entren, en la base de datos
    async adNew(mensajeRecibido) {
       
    const {author, messageDate, text} = mensajeRecibido;                            //Copia en un nuevo arreglo el objeto recibido
    if (!author || !messageDate || !text) {
        return ({error: "Formato del cuerpo incorrecto"})
    }
    try{
        await this.knex(this.nombreTabla).insert(mensajeRecibido);                  //Inserta el nuevo objeto en la base de datos
    }
   catch(error){
    console.log(error);
    }
    }
}

module.exports = Apichat;