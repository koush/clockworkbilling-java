package com.clockworkmod.billing;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.repackaged.com.google.common.util.Base64;

@SuppressWarnings("serial")
public class Clockworkbilling_javaServlet extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain");
        resp.getWriter().println("Hello, world");
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String signedData = req.getParameter("signed_data");
        String signature = req.getParameter("signature");
        String b64PublicKey = req.getParameter("public_key");
        
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            byte[] decodedKey = Base64.decode(b64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            PublicKey pk = keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    
            sig.initVerify(pk);
            sig.update(signedData.getBytes());
            if (!sig.verify(Base64.decode(signature)))
                throw new Exception();
        }
        catch (Exception ex) {
            resp.sendError(500, "signature failure");
        }
    }
}
