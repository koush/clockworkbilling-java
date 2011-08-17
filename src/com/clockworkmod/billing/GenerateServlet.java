package com.clockworkmod.billing;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.repackaged.com.google.common.util.Base64;
import com.google.appengine.repackaged.org.json.JSONObject;

public class GenerateServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(VerifyServlet.class.getSimpleName());

    private static void log(String s, Object... args) {
        logger.info(String.format(s, args));
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            JSONObject ret = new JSONObject();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair pair = keyGen.genKeyPair();
            ret.put("public", Base64.encode(pair.getPublic().getEncoded()));
            ret.put("private", Base64.encode(pair.getPrivate().getEncoded()));
            
            resp.getOutputStream().write(ret.toString().getBytes());
        }
        catch (Exception ex) {
            log("Error: %s", ex);
        }
    }
}
