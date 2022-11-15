from flask import *
import numpy as np
from markupsafe import escape
import pickle
from inputScript import main

app = Flask(__name__)

#use the model
model=pickle.load(open('phishing.pkl',"rb"))


@app.route('/dashboard')
def predict_data():
    return render_template('dashboard.html')


@app.route('/form')
def single_page():
    return render_template('index.html')


@app.route('/predictdata', methods=["GET","POST"])
def get_prediction():
        url = request.form['url']
        print(url)
        print(type(url))
        checking=main(url)
        predicted_value=model.predict(checking)
        value=predicted_value[0]
        val=0
        if value==1:
            val=1
            txt="This is not a phishing website continue to use"
        else:
            val=0
            txt="This is a phishing website"
        return render_template("dashboard.html",predicted='{}'.format(txt),url=url)

if __name__== "__main__":
    app.run(host='0.0.0.0', debug=True)

















































# import importlib
# from optparse import Option
# from flask import Flask, Blueprint, jsonify,render_template
# from flask_cors import CORS
# from flask_restful import Resource, Api
# from simple_app.endpoints import project_api_routes
# import json
# def create_app():
#     web_app = Flask(__name__,template_folder='templates')  
#     CORS(web_app)
#     api1 = Api(web_app)
#     class Actual(Resource):
#          def get(self):
#              f1=open(r'C:/Users/darat/connection/connection/simple_app/info.json')
#              data1=json.load(f1)
#              return data1
#     api1.add_resource(Actual, '/url-upload') # Route_1
#     api_blueprint = Blueprint('api_blueprint', __name__)
#     api_blueprint = project_api_routes(api_blueprint)
#     web_app.register_blueprint(api_blueprint, url_prefix='/api')    
#     # print(simple_app.arima.a)
#     return web_app


# app = create_app()
# #code to run the program
# if __name__ == "__main__":
#     # http_server = WSGIServer(('', 5000), app)
#     # http_server.serve_forever()
#     app.run(host="0.0.0.0",debug=True,use_reloader=False)# to automatically deploy the changes and for development set it true
#                                       # production set it as false