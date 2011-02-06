/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.fracturedatlas.athena.filter;

import com.sun.jersey.spi.container.ContainerRequest;
import com.sun.jersey.spi.container.ContainerRequestFilter;
import java.io.InputStream;
import com.google.gson.Gson;
import com.sun.jersey.core.util.ReaderWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

import org.fracturedatlas.athena.client.audit.PublicAuditMessage;
import org.fracturedatlas.athena.util.Scrubber;
import org.fracturedatlas.athena.web.util.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SimpleAuditFilter implements ContainerRequestFilter {

    protected Logger logger = LoggerFactory.getLogger(this.getClass().getName());
    protected Logger auditFile = LoggerFactory.getLogger("AuditFile");

    protected Gson gson = JsonUtil.getGson();
    protected static List<String> fieldsToScrub = null;
 
    static {
        try {
            Configuration props = new PropertiesConfiguration("audit-client.properties");
             fieldsToScrub = props.getList("audit.fieldsToScrub");
        } catch (ConfigurationException e) {
            Logger tempLog = LoggerFactory.getLogger(SimpleAuditFilter.class);
            tempLog.error(e.getMessage(), e);
        }
    }

    @Override
    public ContainerRequest filter(ContainerRequest request) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InputStream in = request.getEntityInputStream();
            ReaderWriter.writeTo(in, out);
            byte[] requestEntity = out.toByteArray();
            String message = out.toString();
            message = Scrubber.scrubJson(message, fieldsToScrub);
            request.setEntityInputStream(new ByteArrayInputStream(requestEntity));

            PublicAuditMessage pam = constructPublicAuditMessage(request, message);
            sendAuditMessage(pam);

        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
        }
        return request;
    }

    private void sendAuditMessage(PublicAuditMessage pam) {
        auditFile.info(pam.toLogString());
    }

    private PublicAuditMessage constructPublicAuditMessage(ContainerRequest request,
                                                           String message) {

        //TODO: Update this to work with security
        String user = request.getUserPrincipal() + ":";
        String action = request.getMethod();
        String resource = request.getRequestUri().toString();
        return new PublicAuditMessage(user, action, resource, message);
    }


}
