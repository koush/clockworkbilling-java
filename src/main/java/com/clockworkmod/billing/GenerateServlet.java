package com.clockworkmod.billing;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.json.JSONObject;

public class GenerateServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(VerifyServlet.class.getSimpleName());

    private static void log(String s, Object... args) {
        logger.info(String.format(s, args));
    }

    private static String urlSafe(BigInteger b) {
        byte[] bytes = b.toByteArray();
        int i = 0;
        while (bytes[i] == 0)
            i++;
        bytes = Arrays.copyOfRange(bytes, i, bytes.length);
        return Base64.encodeBase64String(bytes)
        .replace('+', '-') // Convert '+' to '-'
        .replace('/', '_') // Convert '/' to '_'
        .replace('=', ' ').trim(); // Remove ending '='

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
            success.put("public_key", Base64.encodeBase64String(pair.getPublic().getEncoded()));
            success.put("private_key", Base64.encodeBase64String(pair.getPrivate().getEncoded()));
            RSAPublicKey pubKey = (RSAPublicKey)pair.getPublic();;
            success.put("e", urlSafe(pubKey.getPublicExponent()));
            success.put("n", urlSafe(pubKey.getModulus()));

            resp.getOutputStream().write(success.toString().getBytes());
        }
        catch (Exception ex) {
            resp.getOutputStream().write(error.toString().getBytes());
            log("Error: %s", ex);
        }
    }
}
