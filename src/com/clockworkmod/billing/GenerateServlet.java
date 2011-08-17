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
        JSONObject error = new JSONObject();
        JSONObject success = new JSONObject();
        try {
            error.put("success", false);
            success.put("success", true);
        }
        catch (Exception ex) {
        }
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair pair = keyGen.genKeyPair();
            success.put("public_key", Base64.encode(pair.getPublic().getEncoded()));
            success.put("private_key", Base64.encode(pair.getPrivate().getEncoded()));
            
            resp.getOutputStream().write(success.toString().getBytes());
        }
        catch (Exception ex) {
            resp.getOutputStream().write(error.toString().getBytes());
            log("Error: %s", ex);
        }
    }
}
