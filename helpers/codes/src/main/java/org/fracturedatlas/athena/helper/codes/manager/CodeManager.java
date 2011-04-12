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

package org.fracturedatlas.athena.helper.codes.manager;

import org.fracturedatlas.athena.apa.ApaAdapter;
import org.fracturedatlas.athena.apa.model.Ticket;
import org.fracturedatlas.athena.apa.model.TicketProp;
import org.fracturedatlas.athena.helper.codes.model.Code;
import org.fracturedatlas.athena.web.manager.RecordManager;
import org.springframework.beans.factory.annotation.Autowired;


public class CodeManager {

    @Autowired
    RecordManager recordManager;

    @Autowired
    ApaAdapter apa;

    public Code createCode(Code code) {
        Ticket codeTicket = new Ticket();
        TicketProp codeProp = recordManager.buildNewTicketProp("code", code.getCode());
        return null;
    }

}
