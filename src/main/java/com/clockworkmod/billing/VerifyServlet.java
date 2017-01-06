package com.clockworkmod.billing;

import org.apache.commons.codec.binary.Base64;

import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
public class VerifyServlet extends HttpServlet {
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
        String signedData = req.getParameter("signed_data");
        String signature = req.getParameter("signature");
        String b64PublicKey = req.getParameter("public_key");
        
        log(signedData);
        log(signature);
        log(b64PublicKey);
        
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            byte[] decodedKey = Base64.decodeBase64(b64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            PublicKey pk = keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    
            sig.initVerify(pk);
            sig.update(signedData.getBytes());
            if (!sig.verify(Base64.decodeBase64(signature)))
                throw new Exception();
            resp.getOutputStream().write(success.toString().getBytes());
        }
        catch (Exception ex) {
            //resp.sendError(500, "signature failure");
            resp.getOutputStream().write(error.toString().getBytes());
        }
    }
}
