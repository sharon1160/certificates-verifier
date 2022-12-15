from flask import Flask, render_template

import src.verify as utils

app = Flask(__name__)


microsoft_store, google_store, mozilla_store = utils.get_trust_stores()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/truststore/<browser>')
def truststore(browser):
    if browser == 'chrome':
        algs_list = utils.get_keys_algorithms_list(google_store)
        keys_lens = utils.get_keys_length_list(google_store)
        cert_data = {
            'certificates': google_store,
            'count': len(google_store),
            'algs_list': algs_list,
            'keys_lens': keys_lens
        }
        return render_template("google_trust_store/google_trust_store.html", cert_data = cert_data)
    elif browser == 'edge':
        return render_template("microsoft_trust_store/microsoft_trust_store.html", certificates = microsoft_store)
    elif browser == 'mozilla':
        return render_template("mozilla_trust_store/mozilla_trust_store.html", certificates = mozilla_store)
    return render_template("index.html")

if __name__ =='__main__':
    app.run(debug = True)
