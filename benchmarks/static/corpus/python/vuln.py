import os, subprocess, pickle, yaml, hashlib
import tarfile
from flask import render_template_string, request
def h(r):
    os.system("rm " + r.p)                      # EXPECT BHF-404
    subprocess.call(r.c, shell=True)            # EXPECT BHF-404
    pickle.loads(r.b)                           # EXPECT BHF-421
    yaml.load(r.t)                              # EXPECT BHF-421
    eval(r.e)                                   # EXPECT BHF-420
    db.execute("SELECT * FROM t WHERE i=" + r.i)  # EXPECT BHF-419
    hashlib.md5(r.d)                            # EXPECT BHF-422
    api_key = "AKIAsecretvalue123"              # EXPECT BHF-429
    tarfile.open(r.archive).extractall(r.dest)  # EXPECT BHF-542
    render_template_string(request.args.get("tpl"))  # EXPECT BHF-543

def django_security_settings(env, config):
    SECURE_SSL_REDIRECT = False                 # EXPECT BHF-541
    SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=False)  # EXPECT BHF-541
    SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=False, cast=bool)  # EXPECT BHF-541
    env_schema = Env(
        DD_SECURE_SSL_REDIRECT=(bool, False),
    )
    SECURE_SSL_REDIRECT = env("DD_SECURE_SSL_REDIRECT")  # EXPECT BHF-541
