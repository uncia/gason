/*
SQLmap Wrapper for Burpsuite.
Copyright (C) 2011-2012  Daniel Garcia (cr0hn) | dani@iniqua.com | twitter: @ggdaniel

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


package burp.interfaces;

import CustomPlugin.sqlmapplugin;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.registerMenuItem("send to sqlmap", new SQLMapManager());
    }

    @Override
    public void setCommandLineArgs(String[] args) {
        
    }

    @Override
    public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, String remoteHost, int remotePort, boolean serviceIsHttps, String httpMethod, String url, String resourceType, String statusCode, String responseContentType, byte[] message, int[] action) {
        return null;
    }

    @Override
    public void applicationClosing() {
        
    }

    @Override
    public void processHttpMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        
    }
}


class SQLMapManager implements IMenuItemHandler
{

    public void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo) {
        if(messageInfo != null)
        {
            for (int i = 0; i < messageInfo.length; i++)
            {
                try {

                    if(messageInfo != null)
                    {
                        sqlmapplugin.getInstance().AddURL(messageInfo[i]);
                    }
                    
                } catch (Exception ex) {
                    Logger.getLogger(SQLMapManager.class.getName()).log(Level.SEVERE, null, ex);
                }
                
            }
        }else{
            JOptionPane.showMessageDialog(null, "No URL to send.","Message can't be send", JOptionPane.ERROR_MESSAGE);
        }
    }
  
}