const passport                  = require('passport');
const LocalStrategy             = require('passport-local').Strategy;
const Usuario                   = require('./usuarios-modelo');
const { InvalidArggumentError } = require('../erros');
const bcrypt                    = require('bcrypt');

function verificaUsuario(usuario){
    if(!usuario){
        throw new InvalidArggumentError('Usuário não encontrado com o e-mail informado');
    }
}


async function verificarSenha(senha, senhaHash){
    const senhaValida = await bcrypt.compare(senha, senhaHash);
    if(!senhaValida){
        throw new InvalidArggumentError('E-mail ou senha inválidos');
    }
}

passport.use(
    new LocalStrategy(
        {
            usernameField: 'email',
            passwordField: 'senha',
            session: false
        }, async (email, senha, done) => {
            try {
                const usuario = await Usuario.buscaPorEmail(email);
                verificaUsuario(usuario);
                await verificarSenha(senha, usuario.senhaHash);

                done(null, usuario);
            } catch (error) {
                done(error);
            }
        }
    )
);