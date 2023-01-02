


async function compilarPlantillaLogout(usuario) {

    const fetchHBS = await fetch("plantillaNombreLogout.hbs");
    const textHBS = await fetchHBS.text();
    const plantillaDelUsuario = Handlebars.compile(textHBS);
    const nombreUsuario = plantillaDelUsuario({usuario});
    document.getElementById("nombreUsuario").innerHTML = nombreUsuario;
    }
    
    compilarPlantillaLogout();