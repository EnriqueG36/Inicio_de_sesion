//Contiene el objeto de configuración de Knex

module.exports = {
    mariaDB: {
        client: 'mysql',
        connection: {
            host: '127.0.0.1',
            port: 3307,
            user: 'root',
            password: 'MySQL110',
            database: 'desafio7',
        }
    },
    sqlite3: {
        client: 'sqlite3',
        connection: {
            filename: './db/sqlite/historialChat.sqlite'
        },
        useNullAsDefault: true,
    }
}
