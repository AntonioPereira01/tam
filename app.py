from re import T
from flask import Flask, jsonify, request
import psycopg2, jwt
import flask
from datetime import datetime, timedelta
from functools import wraps
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'it\xb5u\xc3\xaf\xc1Q\xb9\n\x92W\tB\xe4\xfe__\x87\x8c}\xe9\x1e\xb8\x0f'

@app.route('/', methods = ["GET"])
def home():
    return "Bem vindo à API!"

#Método para verificar se o Token é valido e se ainda não expirou
def auth_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if "token" not in request.headers or request.headers['token'] == "":
            return jsonify({"Erro": "Token está em falta!"}), 400
            
        try:
            decoded_token = jwt.decode(request.headers['token'], app.config['SECRET_KEY'], algorithms=['HS256'])

            if(decoded_token["expiration"] < str(datetime.now())):
                return jsonify({"Erro": "O Token expirou!"}), 401

        except Exception as e:
            return jsonify({"Erro": "Token inválido"}), 403
        return func(*args, **kwargs)
    return decorated


#Método para fazer login
@app.route('/utilizadores/login', methods=['POST'])
def login():
    content = request.get_json()
    if "username" not in content or "pass" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400
    
    query = """ SELECT * FROM public."utilizador" WHERE username = %s """

    values = [content["username"]]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
                rows = cursor.fetchall()

                if(len(rows) == 0):
                  return jsonify({"Erro": "Utilizador não encontrado"}), 400
                  
                if bcrypt.checkpw(content["pass"].encode('utf-8'), rows[0][2].encode('utf-8')):
                    token = jwt.encode({
                    'idUtilizador': rows[0][0],
                    'usernameUtilizador': rows[0][1],
                    'expiration': str(datetime.now() + timedelta(hours=1))}, app.config['SECRET_KEY'])

                    #Código para enviar o token no header da mensagem
                    response = flask.Response("Token")
                    response.headers['Token'] = token
                    return response     
                else:
                    return jsonify({"Erro": "Utilizador não encontrado"}), 404
                     
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400



#Método para registar um utilizador
@app.route('/utilizadores/registar', methods = ['POST'])
def registar():
    content = request.get_json()

    if "username" not in content or "pass" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400

    passEncrypt = bcrypt.hashpw(content['pass'].encode('utf-8'), bcrypt.gensalt())

    query1 = """SELECT * FROM UTILIZADOR WHERE username = %s"""

    query2 = """INSERT INTO public."utilizador" (username, pass) VALUES(%s, %s)"""

    values1 = [content['username']]
    values = [content["username"], passEncrypt.decode('utf-8')]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query1, values1)
                rows = cursor.fetchall()

                if len(rows) > 0:
                    return jsonify({"Erro": "Já existe um utilizador com o username inserido"}), 409
                
                cursor.execute(query2, values)

        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code":200}


#Método para inserir uma lista
@app.route('/listas/inserir', methods=['POST'])
@auth_user
def inserirLista():
    contentBody = request.get_json()
    token = request.headers['token']

    if "nome" not in contentBody:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400
    
    token_decode = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    query = """ INSERT INTO public."lista" (u_id, nome) VALUES (%s, %s)"""

    values = [token_decode["idUtilizador"], contentBody["nome"]]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}

@app.route('/tarefas/inserir', methods=['POST'])
@auth_user
def inserirTarefa():
    contentBody = request.get_json()
    if "l_id" not in contentBody or "descricao" not in contentBody or "dataLimite" not in contentBody or "horaLimite" not in contentBody or "estado" not in contentBody:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400


    data = datetime.strptime(contentBody["dataLimite"], '%d/%m/%Y')

    query = """ INSERT INTO public."tarefa" (l_id, descricao, data_limite, hora_limite, estado) VALUES (%s, %s, %s, %s, %s )"""
    values = [contentBody["l_id"], contentBody["descricao"], data, contentBody["horaLimite"], contentBody["estado"]]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}


#Método para obter as listas de um determinado utilizador
@app.route('/listas', methods=['GET'])
@auth_user
def obterListas():
    content = request.headers['token']

    conn = ligacaoBD()
    cur = conn.cursor() 

    listas = []

    token_decode = jwt.decode(content, app.config['SECRET_KEY'], algorithms=['HS256'])
    cur.execute("SELECT * FROM lista WHERE u_id = %s;", (token_decode["idUtilizador"],))
    rows = cur.fetchall()

    for row in rows:
        listas.append({"id": row[0], "nome": row[2]})
    conn.close()
    return jsonify(listas), 200

#Método para obter as tarefas de uma determinada lista
@app.route('/lista/tarefas', methods=['GET'])
@auth_user
def obterTarefasLista():

    if request.args.get('l_id') == "":
        return jsonify({"Erro": "Parâmetros inválidos"}), 400

    conn = ligacaoBD()
    cur = conn.cursor()

    tarefas = []

    cur.execute("SELECT * FROM tarefa WHERE l_id = %s ORDER BY data_limite", (request.args.get('l_id'),))
    rows = cur.fetchall()

    for row in rows: 
        tarefas.append({"id": row[0], "l_id": row[1], "descricao": row[2], "dataLimite": row[3].strftime('%d/%m/%Y'), "horaLimite": row[4], "estado": row[5]})
    conn.close()
    return jsonify(tarefas), 200

#Método para obter as tarefas de todas as listas de um utilizador
@app.route('/listas/tarefas', methods=['GET'])
@auth_user
def obterTarefasTodas():
    conn = ligacaoBD()
    cur = conn.cursor()

    tarefas = []

    token_decode = jwt.decode(request.headers['token'], app.config['SECRET_KEY'], algorithms=['HS256'])

    cur.execute("SELECT * FROM tarefa WHERE l_id  IN (SELECT l_id FROM lista WHERE u_id IN (SELECT u_id FROM utilizador WHERE u_id = %s )) ORDER BY data_limite", (token_decode["idUtilizador"],) )
    rows = cur.fetchall()
    for row in rows:
        tarefas.append({"id": row[0], "l_id": row[1], "descricao": row[2], "dataLimite": row[3].strftime('%d/%m/%Y'), "horaLimite": row[4], "estado": row[5]})
    conn.close()
    return jsonify(tarefas), 200

#Método para remover uma lista
@app.route('/listas/remover', methods=['DELETE'])
@auth_user
def removerLista():
    if request.args.get('l_id') == None:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400

    query = """DELETE FROM public."lista" WHERE l_id = %s"""

    values = [request.args.get('l_id')]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}


#Método para remover uma tarefa
@app.route('/tarefas/remover', methods=['DELETE'])
@auth_user
def removerTarefa():

    if request.args.get('t_id') == None:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400

    query = """DELETE FROM public."tarefa" WHERE t_id = %s"""

    values = [request.args.get('t_id')]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}


#Método para concluir uma tarefa(muda o estado da tarefa para true)
@app.route('/tarefas/concluir', methods=['PUT'])
@auth_user
def concluirTarefa():

    if request.args.get('t_id') == None:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400

    query = """UPDATE public."tarefa" SET estado = %s WHERE t_id = %s"""

    values = ["true", request.args.get('t_id')]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}


#Método para atualizar as listas
@app.route('/listas/atualizar', methods=['PUT'])
@auth_user
def atualizarLista():
    content = request.get_json()

    if "nome" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400
    
    query = """UPDATE public."lista" SET nome = %s WHERE l_id = %s"""

    values = [content["nome"], content["id"]]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}


#Método para atualizar as tarefas
@app.route('/tarefas/atualizar', methods=['PUT'])
@auth_user
def atualizarTarefa():
    content = request.get_json()

    if "id" not in content or "descricao" not in content or "dataLimite" not in content or "horaLimite" not in content:
        return jsonify({"Erro": "Parâmetros inválidos"}), 400
    
    query = """UPDATE public."tarefa" SET descricao = %s, data_limite = %s, hora_limite = %s WHERE t_id = %s"""


    data = datetime.strptime(content["dataLimite"], '%d/%m/%Y')

    values = [content["descricao"], data, content["horaLimite"], content["id"]]

    try:
        with ligacaoBD() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Erro": str(error)}), 400

    return {"Code": 200}

#Método para conectar a BD
def ligacaoBD():
    conn = psycopg2.connect(
        host="ec2-52-30-75-37.eu-west-1.compute.amazonaws.com",
        dbname="ddjkeli6g9iube",
        user="csyhyojjtfoznc",
        password="0e6742bd8109b828efe2ba61a59c8d896338faee293cd0d44f9e7282b2610b39"
    )
    return conn

if __name__ == "__main__":

    app.run(port=8080, debug=True, threaded=True)

