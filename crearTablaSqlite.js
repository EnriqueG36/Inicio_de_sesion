//Este script solo contiene la sintaxys para crear la tabla en sqlite que requiere el desafío

const dbConfig = require('./db/config.js');     //importamos el archivo de configuracion para Knex
const knex = require('knex')(dbConfig.sqlite3);  //Importamos knex y le configuramos para usar sqlite

//Crea la tabla tablaChat en la base de datos sqlite
 
/*
(async () => {
    await knex.schema.createTable('tablaChat', (table) => {
        table.increments('id');
        table.string('author').notNullable();
        table.string('messageDate');
        table.string('text');
    });
    console.log("Tabla creada");
}
);
*/


const createTables = async () => {

    try {
       //await knex.schema.dropTableIfExist('tablachat');         Revisar nombre de la funcion

        await knex.schema.createTable('tablachat', (table) => {
            
        table.increments('id');
        table.string('author').notNullable();
        table.string('messageDate');
        table.string('text');


        });

        await knex.destroy();
        console.log('tablachat creada');
    }
    catch(error) {
        console.log ('error al crear la tabla');
        console.log(error.message);
    }

}

createTables();