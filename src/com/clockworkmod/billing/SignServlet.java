package com.clockworkmod.billing;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.repackaged.com.google.common.util.Base64;
import com.google.appengine.repackaged.org.json.JSONObject;

public class SignServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(VerifyServlet.class.getSimpleName());

    private static void log(String s, Object... args) {
        logger.info(String.format(s, args));
    }
    
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain");
        resp.getWriter().println("Hello, world");
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        JSONObject error = new JSONObject();
        JSONObject success = new JSONObject();
        try {
            error.put("success", false);
            success.put("success", true);
        }
        catch (Exception ex) {
        }
        String data = req.getParameter("data");
        String b64PrivateKey = req.getParameter("private_key");

        try {
            byte[] privateKey = Base64.decode(b64PrivateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKey);
            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(privSpec);

            Signature dsa = Signature.getInstance("SHA1withRSA");
            dsa.initSign(privKey);
            dsa.update(data.getBytes());
            byte[] signed = dsa.sign();
            
            String b64Signed = Base64.encode(signed);
            success.put("signature", b64Signed);
            resp.getOutputStream().write(success.toString().getBytes());
        }
        catch (Exception ex) {
            //resp.sendError(500, "signature failure");
            resp.getOutputStream().write(error.toString().getBytes());
        }
    }
}
