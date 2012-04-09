/*
SQLmap Wrapper for Burpsuite.
Copyright (C) 2011-2012  Daniel Garcia (cr0hn) | dani@iniqua.com | twitter: @ggdaniel

Based on code of @NighterMan

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package CustomPlugin;

import burp.interfaces.IHttpRequestResponse;

/**
 *
 * @author Daniel Garcia Garcia (cr0hn) - dani@iniqua.com
 */
public class HTTPDataTransform {
   
   public static String getCookie(IHttpRequestResponse currentMessageInfo)
   {
      int cookiePos = 0;
      int endLine = 0;
      String cookie = "";
      String request = null;

      try {

         if(currentMessageInfo != null)
         {
             request = new String(currentMessageInfo.getRequest());

             /* GET Cookie Position */
             if(request != null)
             {
                 cookiePos = request.indexOf("Cookie:");
                 if (cookiePos != -1) {
                    endLine = request.indexOf("\r\n", cookiePos);
                    cookie = request.substring(cookiePos + 8, endLine);
                 }
             }
        }

      } catch (Exception ex) {
         ex.printStackTrace();
      }


      return cookie;
   }


   public static String getPOSTData(IHttpRequestResponse currentMessageInfo)
   {
      int postPos = 0;
      int endLine = 0;
      String post = "";
      String request = null;

      try {

         if(currentMessageInfo != null)
         {
             request = new String(currentMessageInfo.getRequest());
            /* GET POST DATA Position */
             if(request != null)
             {
                 /* GET POST DATA Position */
                 postPos = request.indexOf("\r\n\r\n");
                 if (postPos != -1) {
                    endLine = request.indexOf("\r\n\r\n", postPos);
                    post = request.substring(postPos + 4, request.length());
                 }
             }
          }

      } catch (Exception ex) {
         ex.printStackTrace();
      }


      return post;
   }


   public static String getMethod(IHttpRequestResponse currentMessageInfo)
   {
      String method = "";
      String request = null;

      try {

         request = new String(currentMessageInfo.getRequest());

          if(currentMessageInfo != null)
         {
             request = new String(currentMessageInfo.getRequest());
            /* GET Request Method */
             if(request != null)
             {
                 if(request.indexOf("GET") == 0)
                    return "GET";
                 else if (request.indexOf("POST") == 0)
                    return "POST";
             }
          }

      } catch (Exception ex) {
         ex.printStackTrace();
      }


      return method;
   }
}
