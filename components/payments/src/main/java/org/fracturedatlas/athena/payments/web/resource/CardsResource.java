/*

ATHENA Project: Management Tools for the Cultural Sector
Copyright (C) 2010, Fractured Atlas

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/

*/

package org.fracturedatlas.athena.payments.web.resource;

import com.google.gson.Gson;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import org.fracturedatlas.athena.payments.manager.CardsManager;
import org.fracturedatlas.athena.payments.model.CreditCard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


@Component
@Path("/cards/")
@Consumes({"application/json"})
@Produces({"application/json"})
public class CardsResource {

    Gson gson = new Gson();

    @Autowired
    CardsManager cardsManager;

    @GET
    @Path("{id}")
    public Object get(@PathParam("id") String id) {
        return gson.toJson(cardsManager.get(id));
    }

    @POST
    @Path("")
    public Object save(String json) {
        CreditCard card = gson.fromJson(json, CreditCard.class);
        card = cardsManager.save(card);
        return gson.toJson(card);
    }

    @PUT
    @Path("{id}")
    public Object update(@PathParam("id") String id, String json) {
        CreditCard card = gson.fromJson(json, CreditCard.class);
        card.setId(id);
        card = cardsManager.save(card);
        return gson.toJson(card);
    }

    @DELETE
    @Path("{id}")
    public void delete(@PathParam("id") String id) {
        cardsManager.delete(id);
    }
}