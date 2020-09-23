const { response } = require('express');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');
const Usuario = require('../models/usuario');

const crearUsuario = async (req, res = response) => {

    const { email, password } = req.body;
    try {
        let usuario = await Usuario.findOne({ email });
        if (usuario) { 
            return res.status(400).json({
                ok: false,
                msg: 'Credenciales no validas'
            });
        }
        usuario = new Usuario( req.body );
        // Encriptar contraseña
        var salt = bcrypt.genSaltSync(10);
        usuario.password = bcrypt.hashSync( password, salt );
        await usuario.save();
        // Generar JWT
        const token = await generarJWT(usuario.id, usuario.name);
        res.status(201).json({ 
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Por favor hable con el administrador'
        });
    }
};

const loginUsuario = async (req, res = response) => {
    const { email, password } = req.body;
    
    try {
        const usuario = await Usuario.findOne({ email });
        if (!usuario) { 
            return res.status(400).json({
                ok: false,
                msg: 'Usuario no existe'
            });
        }
        // Confirmar password
        const validPassword = bcrypt.compareSync(password, usuario.password);
        if ( !validPassword ) {
            return res.status(400).json({
                ok: false,
                msg: 'Credenciales incorrectas'
            });
        }
        // generar JWT
        const token = await generarJWT(usuario.id, usuario.name);
        res.status(201).json({ 
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token
        });
        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Por favor hable con el administrador'
        });
    }
};

const revalidarToken = async (req, res = response) => {
    const { uid, name } = req;
    // generar un nuevo JWT
    const token = await generarJWT(uid, name);
    res.json({ 
        ok: true,
        uid,
        name,
        token
    });
};

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}
