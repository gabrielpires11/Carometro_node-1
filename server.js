// importando das biblioteca
const express = require('express'); // biblioteca 
const mysql = require('mysql2'); // Conectar com o banco de dados
const cors = require('cors'); // trabalhar com API
const bodyParser = require('body-parser'); //pegar requisição do corpo do html
const session = require('express-session'); // sessão para login
const bcrypt = require('bcrypt'); // fazer a criptografia da senha 
require('dotenv').config(); // arquivos de configuração

const app = express();

app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // para pegar o corpo do html

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect(error => {
    if (error) {
        console.error(
            'Erros ao conectar com banco de dados', err)
        return;
    }
    console.log('Conectado ao banco de dados')
}
);

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const authenticateSession = (req, res, next) => {
    if (!req.session.userID) {
        return res.status(401).send('Acesso negado, faça login para continuar!')
    }
    next();
}

app.post('/login', (req, res) => {
    const { cpf, senha } = req.body;

    db.query('SELECT * FROM usuarios WHERE cpf = ? AND senha = ?', [cpf], // query para verificar se o cpf existe no banco de dados
        async (err, results) => {
            if (err) return res.status(500).send('Server com erro');
            if (results.length === 0) {
                return res.status(500).send('CPF ou senha incorretos');

                const usuario = results[0];
                const senhaCorreta = await bcrypt.compare(senha, usuario.senha)
                if (!senhaCorreta) return res.status(500).send(
                    'CPF ou senha incorretos');

                req.session.userID = usuario.idUsuarios;
                console.log('idUsuarios:', usuario.idUsuarios);
                res.json({ message: 'Login bem-sucedido!' });
            }
        })
})

app.post('/cadastro', (req, res) => {
    const { cpf, senha, nome, email, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios } = req.body;
    cep = cep.replace(/-/g, '');
    db.query(
        'SELECT cpf FROM usuarios WHERE cpf = ?', [cpf], async (err, results) => {
            if (err) {
                console.error('Erro ao consultar o CPF:', err)

                return res.status(500).json({ message: 'Erro ao verificar o CPF' });


            }
            if (results.length > 0) {
                return res.status(400).json({ message: 'CPF já cadastrado' });
            }

            const senhacripto = await bcrypt.hash(senha, 10);
            //primeiro argumento é variavel a ser cripto
            //segundo argumento é o custo do hash

            db.query('INSERT INTO usuarios (nome, email, cpf, senha, celular, cep, logradouro, bairro, cidade, estado, imagem, Tipos_Usuarios_idTipos_Usuarios VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
            [nome, email, cpf, senhacripto, celular, cep, logradouro, 
                bairro, cidade, estado, Tipos_Usuarios_idTipos_Usuarios,
                imagem
            ], (err, results)=>{
                if(err){
                    console.error('Erro ao inserir usuário', err);
                    return res.status(500).json({ 
                        message: 'Erro ao cadastrar usuário.' 
                    });
                }

                console.log('Usuário inserido com sucesso:'
                    ,results.idUsuarios
                );
                res.status(200).json({message: 'Usuário cadastrado com sucesso!'})
            }
        }

    )
})

app.use(express.static('/src'));
app.use(express.static(__dirname + '/src'));

app.get('/login', (req,res) => {
    res.sendFile(__dirname + '/src/login.html')
})

app.get('/cadastro', (req,res) => {
    res.sendFile(__dirname + '/src/cadastroUsuarios.html')
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`)
}
);