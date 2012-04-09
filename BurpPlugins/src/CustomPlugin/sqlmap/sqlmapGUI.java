/*
    GASON: SQLmap Wrapper for Burpsuite.
    Copyright (C) 2011-2012  Daniel Garcia (cr0hn) | dani@iniqua.com | twitter: @ggdaniel
    Project page: http://code.google.com/p/gason/

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

/*
 * NewJFrame.java
 *
 * Created on 16-feb-2012, 15:30:03
 */

package CustomPlugin.sqlmap;

import CustomPlugin.HTTPDataTransform;
import burp.IHttpRequestResponse;
import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;


/**
 *
 * @author Daniel Garcia Garcia (cr0hn) - dani@iniqua.com
 */
public class sqlmapGUI extends javax.swing.JFrame {

    //private ArrayList<IHttpRequestResponse> URLs = new ArrayList<IHttpRequestResponse>(30);

    private Map<String,IHttpRequestResponse> URLs = new HashMap<String, IHttpRequestResponse>(30);
    private Integer tabnum = 0;
    private ArrayList<Thread> tabs = new ArrayList<Thread>(20);
    private static String command = "/usr/bin/sqlmap";


    public sqlmapGUI()
    {
        initComponents();

        this.getRootPane().setDefaultButton(this.bnt_run);
        this.setLocationRelativeTo(null);
        this.setVisible(false);
    }

    public void AddURL(IHttpRequestResponse URLs_) throws Exception{

        if(URLs_ != null && URLs_.getUrl().toString() != null)
        {
            // URL
            this.URLs.put(URLs_.getUrl().toString(), URLs_);

            // Configure GUI components
            this.cmb_urls.addItem(URLs_.getUrl().toString());

            // Find binary of sqlmap
            if(!(new File(sqlmapGUI.command).exists()))
            {
                txt_bin.setForeground(Color.RED);
                txt_bin.setText(sqlmapGUI.command + " NOT FOUND. Select executable!");
                bnt_run.setEnabled(false);
            }else
            {
                txt_bin.setText(sqlmapGUI.command);
            }

            this.cmb_urls.setSelectedIndex(this.cmb_urls.getItemCount()-1);

            // Configure components
            this.configureGUI(URLs_.getUrl().toString());
        }

    }

    

    private void configureGUI(String url) throws Exception
    {
        // Looking for URL
        if(this.URLs.size() > 0 && url != null)
        {
            IHttpRequestResponse l_req = this.URLs.get(url);

            String m_method = HTTPDataTransform.getMethod(l_req).toLowerCase();

            // Select method: POST/GET
            for(int i=0; i < this.cmb_method.getItemCount(); i++)
            {
                if (this.cmb_method.getItemAt(i).toString().toLowerCase().equals(m_method))
                {
                    this.cmb_method.setSelectedIndex(i);
                    break;
                }
            }

           // Set cookie
           txt_cookie.setText(HTTPDataTransform.getCookie(l_req));
           
           // Reset params list
           this.lst_params.setModel(new DefaultComboBoxModel());

           // Fill parameters list
           ArrayList<String> l_params = null;
           if("get".equals(m_method))
           {
               if (l_req.getUrl().getQuery() != null)
               {
                    l_params = this._getParameters(l_req.getUrl().getQuery());
               }
           }else
           {
                if("post".equals(m_method))
                {
                    l_params = this._getParameters(HTTPDataTransform.getPOSTData(l_req));
                }
           }

           if(l_params != null)
                this.lst_params.setModel(new DefaultComboBoxModel((Object[])l_params.toArray()));

           txt_command.setText(this.GetCommandString(url));
       }
    }

    /**
     * Get an array with each GET parameter of URL
     *
     * @param query: Raw URL string
     * @return Array list with parsed parameters.
     */
    private ArrayList<String> _getParameters(String query)
    {
        if(query == null || "".equals(query))
            return null;

        ArrayList<String> l_list = new ArrayList<String>(15);

        if(query != null && !query.isEmpty())
        {
           String l_url_splited[] = query.split("&");

           for (int param = 0; param < l_url_splited.length; param++)
           {
               String l_param[] = l_url_splited[param].split("=");
               if(l_param.length > 0)
               {
                   String l_param_new = l_param[0];
                   if(l_param.length > 1)
                       l_param_new += "=" + l_param[1];

                   l_list.add(l_param_new);
               }
           }
        }

       return l_list;
    }

    private List<String> GetCommand(String url)
    {
        List<String> l_params = new ArrayList<String>();

        String l_dbms[] = {"","mysql", "oracle", "postgresql", "mssql", "access", "sqlite", "firebird", "sybase", "maxdb", "db2"};
        String l_action[] = {"","--users", "--passwords", "--privileges", "--roles", "--dbs", "--tables", "--columns", "--schema", "--dump", "--dump-all"};
        String l_tampers[] = {"apostrophemask","appendnullbyte","base64encode","between","chardoubleencode","charencode","charunicodeencode","equaltolike","halfversionedmorekeywords","ifnull2ifisnull","modsecurityversioned","modsecurityzeroversioned","multiplespaces","percentage","randomcase","randomcomments","securesphere","space2comment","space2dash","space2hash","space2morehash","space2mssqlblank","space2mssqlhash","space2mysqlblank","space2mysqldash","space2plus","space2randomblank","unmagicquotes","versionedkeywords","versionedmorekeywords"};
        String l_optimizations[] = {"-o", "--predict-output", "--keep-alive", "--null-connection"};

        // Add command
        l_params.add(txt_bin.getText());

        String m_url = url;

        //
        // Action
        //
        l_params.add(l_action[cmb_action.getSelectedIndex()]);


        if (!cmb_dbms.getSelectedItem().equals("Auto"))
        {
            l_params.add("--dbms=" + l_dbms[cmb_dbms.getSelectedIndex()]);
        }

        if (chk_random_user_agent.isSelected())
        {
            l_params.add("--random-agent");
        }

        if (txt_cookie.getText() != null && !txt_cookie.getText().equals(""))
        {
            l_params.add("--cookie=\"" + txt_cookie.getText() + "\"");
        }

        // Max count number of elements
        try
        {
            if (!txt_count.getText().isEmpty())
            {
                int val = Integer.parseInt(txt_count.getText());

                if(val < 1)
                {
                    JOptionPane.showMessageDialog(this, "Text must be a numeric value", "Value error", JOptionPane.ERROR_MESSAGE);
                    txt_count.requestFocus();
                    txt_count.selectAll();
                }else
                {
                    l_params.add("--count");
                    l_params.add(txt_count.getText());
                }
            }

        }catch(Exception e)
        {
            JOptionPane.showMessageDialog(this, "Text must be a numeric value", "Value error", JOptionPane.ERROR_MESSAGE);
            txt_count.requestFocus();
            txt_count.selectAll();
        }

        //
        // Select parsers
        //
        Component[] c = this.jpn_tampers.getComponents();
        ArrayList<String> m_parses = new ArrayList<String>();
        for (int i = 0; i < c.length; i++)
        {
            for(int comp = 0; comp < l_tampers.length; comp++)
            {
                JCheckBox l_chk = (JCheckBox)c[i];

                if (l_chk.isSelected())
                {
                    if (l_tampers[comp].equals(l_chk.getText()))
                    {
                        m_parses.add(l_tampers[comp]);
                    }
                }
            }
        }
        String m_tamper = "";
        for (int i = 0; i < m_parses.size(); i++)
        {
            m_tamper += m_parses.get(i);
            if(i + 1 != m_parses.size())
                m_tamper+=",";
        }
        if (!m_tamper.isEmpty())
        {
            l_params.add("--tamper=" + m_tamper);
        }


        //
        // Optimization
        //
        if(chk_optimization_all.isSelected())
            l_params.add("-o");
        if(chk_optimization_page_lenth.isSelected())
            l_params.add("--null-connection");
        if(chk_optimization_persistent.isSelected())
            l_params.add("--keep-alive");
        if(chk_optimization_predict.isSelected())
            l_params.add("--predict-output");
        // Threads
        try
        {
            int val = Integer.parseInt(txt_optimization_threads.getText());

            if(val < 1)
            {
                JOptionPane.showMessageDialog(this, "Text must be a numeric value", "Value error", JOptionPane.ERROR_MESSAGE);
                txt_optimization_threads.requestFocus();
                txt_optimization_threads.selectAll();
            }else
            {
                if(!txt_optimization_threads.getText().equals("1"))
                {
                    l_params.add("--threads");
                    l_params.add(txt_optimization_threads.getText());
                }
            }

        }catch(Exception e)
        {
            JOptionPane.showMessageDialog(this, "Text must be a numeric value", "Value error", JOptionPane.ERROR_MESSAGE);
            txt_optimization_threads.requestFocus();
            txt_optimization_threads.selectAll();
        }


        //
        // Fingerprint
        //
        if(chk_fingerprint.isSelected())
        {
            l_params.add("-f");
        }

        //
        // Risk
        //
        if (!cmb_risk.getSelectedItem().toString().equals("-"))
        {
            l_params.add("--risk="+cmb_risk.getSelectedItem().toString());
        }

        //
        // Level
        //
        if (!cmb_level.getSelectedItem().toString().equals("-"))
        {
            l_params.add("--level="+cmb_level.getSelectedItem().toString());
        }

        //
        // Verbose
        //
        if(chk_verbose.isSelected())
        {
            l_params.add("-v");
            l_params.add("2");
        }


        //
        // Add params to analize
        //
        Object l_params_values[] = lst_params.getSelectedValues();
        if (l_params_values.length > 0)
        {
            l_params.add("-p");

            String l_p = "";
            for(int p = 0; p < l_params_values.length; p++)
            {
                String l_p_splited[] = l_params_values[p].toString().split("=");
                
                if(l_p_splited.length > 0)
                {
                    l_p += l_p_splited[0];

                    if (p + 1 != l_params_values.length)
                    {
                        l_p += ",";
                    }
                }
            }
            l_params.add(l_p);
        }

        //
        // Add POST data
        //
        if(cmb_method.getSelectedItem().toString().equals("POST"))
        {
            try {
                // Looking for URL
                IHttpRequestResponse l_req = this.URLs.get(cmb_urls.getSelectedItem());

                if (l_req.getUrl().toString().equals(cmb_urls.getSelectedItem()))
                {
                    // If parameters aren't in POST, get it form URL
                    if(!HTTPDataTransform.getPOSTData(l_req).isEmpty())
                    {
                        l_params.add("--data=\"");
                        // Replace for fix Linux command line errors
                        l_params.add(HTTPDataTransform.getPOSTData(l_req).replace("!", "\\!"));
                        l_params.add("\"");
                    }else // If method is GET => force to POSTf
                    {
                        l_params.add("--data=\"");
                        l_params.add(l_req.getUrl().getQuery());
                        l_params.add("\"");
                    }
                    
                }

            } catch (Exception ex) {
                    Logger.getLogger(sqlmapGUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
        {
            // If data is into POST, foce to GET
            IHttpRequestResponse l_req = this.URLs.get(cmb_urls.getSelectedItem());
            m_url += HTTPDataTransform.getPOSTData(l_req);
        }

        //
        // Database configuracion
        //
        if(!txt_bbdd.getText().isEmpty())
        {
            l_params.add("-D");
            l_params.add(txt_bbdd.getText());
        }
        if(!txt_table.getText().isEmpty())
        {
            l_params.add("-T");
            l_params.add(txt_table.getText());
        }
        if(!txt_column.getText().isEmpty())
        {
            l_params.add("-C");
            l_params.add(txt_column.getText());
        }
        if(!txt_user.getText().isEmpty())
        {
            l_params.add("-U");
            l_params.add(txt_user.getText());
        }

        //
        // url
        //
        l_params.add("-u");
        l_params.add(m_url);

        return l_params;
    }

    private String GetCommandString(String url)
    {
        List<String> m_commands = this.GetCommand(url);
        StringBuilder m_command_string = new StringBuilder(500);

        for(int i = 0; i < m_commands.size(); i++)
        {
            m_command_string.append(m_commands.get(i));
            m_command_string.append(" ");
        }

        return m_command_string.toString();

    }

    private void Execute(String url)
    {

        try {
            List<String> m_command = this.GetCommand(url);

            if(chk_debug.isSelected())
                System.out.println("[Debug] Command to run: " + this.GetCommandString(url));

            // Execute
            sqlmapTab pt = new sqlmapTab(m_command, this.cmb_urls.getSelectedItem().toString(), this.tbl_main, chk_debug.isSelected());
            Thread tr = new Thread(pt);

            // Add to tabs container and thread list
            this.tbl_main.addTab(this.tabnum.toString(), pt);
            this.tabs.add(tr);
            this.tabnum++;

            // Run
            pt.run();


        } catch (Exception ex) {
            Logger.getLogger(sqlmapGUI.class.getName()).log(Level.SEVERE, null, ex);
        }

    }





    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jDialog1 = new javax.swing.JDialog();
        jDialog2 = new javax.swing.JDialog();
        jDialog3 = new javax.swing.JDialog();
        jScrollPane2 = new javax.swing.JScrollPane();
        tbl_main = new javax.swing.JTabbedPane();
        jPanel4 = new javax.swing.JPanel();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        cmb_urls = new javax.swing.JComboBox();
        cmb_method = new javax.swing.JComboBox();
        jLabel7 = new javax.swing.JLabel();
        txt_cookie = new javax.swing.JTextField();
        jLabel12 = new javax.swing.JLabel();
        txt_bin = new javax.swing.JTextField();
        btn_select_bin = new javax.swing.JButton();
        jLabel14 = new javax.swing.JLabel();
        txt_command = new javax.swing.JTextField();
        btn_del = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jPanel5 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        cmb_dbms = new javax.swing.JComboBox();
        jLabel3 = new javax.swing.JLabel();
        cmb_action = new javax.swing.JComboBox();
        jLabel5 = new javax.swing.JLabel();
        cmb_level = new javax.swing.JComboBox();
        jLabel6 = new javax.swing.JLabel();
        cmb_risk = new javax.swing.JComboBox();
        jLabel4 = new javax.swing.JLabel();
        txt_count = new javax.swing.JTextField();
        chk_random_user_agent = new javax.swing.JCheckBox();
        chk_verbose = new javax.swing.JCheckBox();
        chk_fingerprint = new javax.swing.JCheckBox();
        jPanel6 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        txt_bbdd = new javax.swing.JTextField();
        txt_table = new javax.swing.JTextField();
        txt_column = new javax.swing.JTextField();
        txt_user = new javax.swing.JTextField();
        jpn_tampers = new javax.swing.JPanel();
        chk_ifnull2ifisnull = new javax.swing.JCheckBox();
        chk_equaltolike = new javax.swing.JCheckBox();
        chk_multiplespaces = new javax.swing.JCheckBox();
        chk_apostrophemask = new javax.swing.JCheckBox();
        chk_percentage = new javax.swing.JCheckBox();
        chk_securesphere = new javax.swing.JCheckBox();
        chk_randomcomments = new javax.swing.JCheckBox();
        chk_space2randomblank = new javax.swing.JCheckBox();
        chk_halfversionedmorekeywords = new javax.swing.JCheckBox();
        chk_versionedkeywords = new javax.swing.JCheckBox();
        chk_space2morehash = new javax.swing.JCheckBox();
        chk_space2hash = new javax.swing.JCheckBox();
        chk_appendnullbyte = new javax.swing.JCheckBox();
        chk_base64encode = new javax.swing.JCheckBox();
        chk_between = new javax.swing.JCheckBox();
        chk_chardoubleencode = new javax.swing.JCheckBox();
        chk_charencode = new javax.swing.JCheckBox();
        chk_space2plus = new javax.swing.JCheckBox();
        chk_modsecurityversioned = new javax.swing.JCheckBox();
        chk_modsecurityzeroversioned = new javax.swing.JCheckBox();
        chk_versionedmorekeywords = new javax.swing.JCheckBox();
        chk_space2mssqlblank = new javax.swing.JCheckBox();
        chk_space2mssqlhash = new javax.swing.JCheckBox();
        chk_space2mysqlblank = new javax.swing.JCheckBox();
        chk_space2mysqldash = new javax.swing.JCheckBox();
        chk_charunicodeencode = new javax.swing.JCheckBox();
        chk_space2dash = new javax.swing.JCheckBox();
        chk_unmagicquotes = new javax.swing.JCheckBox();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        lst_params = new javax.swing.JList();
        jLabel15 = new javax.swing.JLabel();
        jPanel7 = new javax.swing.JPanel();
        chk_optimization_all = new javax.swing.JCheckBox();
        chk_optimization_predict = new javax.swing.JCheckBox();
        chk_optimization_persistent = new javax.swing.JCheckBox();
        chk_optimization_page_lenth = new javax.swing.JCheckBox();
        jLabel13 = new javax.swing.JLabel();
        txt_optimization_threads = new javax.swing.JTextField();
        chk_debug = new javax.swing.JCheckBox();
        bnt_run = new javax.swing.JButton();
        btn_cancel = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();

        javax.swing.GroupLayout jDialog1Layout = new javax.swing.GroupLayout(jDialog1.getContentPane());
        jDialog1.getContentPane().setLayout(jDialog1Layout);
        jDialog1Layout.setHorizontalGroup(
            jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE)
        );
        jDialog1Layout.setVerticalGroup(
            jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout jDialog2Layout = new javax.swing.GroupLayout(jDialog2.getContentPane());
        jDialog2.getContentPane().setLayout(jDialog2Layout);
        jDialog2Layout.setHorizontalGroup(
            jDialog2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE)
        );
        jDialog2Layout.setVerticalGroup(
            jDialog2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout jDialog3Layout = new javax.swing.GroupLayout(jDialog3.getContentPane());
        jDialog3.getContentPane().setLayout(jDialog3Layout);
        jDialog3Layout.setHorizontalGroup(
            jDialog3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE)
        );
        jDialog3Layout.setVerticalGroup(
            jDialog3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE)
        );

        setTitle("SQLMap wrapper v0.9.5 - by Cr0hn (@ggdaniel)");
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
        });
        getContentPane().setLayout(new java.awt.GridLayout(1, 0));

        jScrollPane2.setMinimumSize(new java.awt.Dimension(50, 50));
        jScrollPane2.setPreferredSize(new java.awt.Dimension(590, 660));

        tbl_main.setMinimumSize(new java.awt.Dimension(50, 50));
        tbl_main.setPreferredSize(new java.awt.Dimension(550, 640));

        jPanel4.setMinimumSize(new java.awt.Dimension(50, 50));
        jPanel4.setPreferredSize(new java.awt.Dimension(550, 640));
        jPanel4.setLayout(null);

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Target"));
        jPanel1.setLayout(null);

        jLabel1.setText("URL");
        jPanel1.add(jLabel1);
        jLabel1.setBounds(10, 20, 24, 15);

        cmb_urls.setName("cmb_method"); // NOI18N
        cmb_urls.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                cmb_urlsPropertyChange(evt);
            }
        });
        jPanel1.add(cmb_urls);
        cmb_urls.setBounds(40, 20, 390, 20);

        cmb_method.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "GET", "POST" }));
        cmb_method.setEditor(null);
        cmb_method.setName("cmb_method"); // NOI18N
        jPanel1.add(cmb_method);
        cmb_method.setBounds(510, 20, 60, 20);

        jLabel7.setText("Cookie");
        jPanel1.add(jLabel7);
        jLabel7.setBounds(10, 50, 44, 15);

        txt_cookie.setEditable(false);
        txt_cookie.setName("txt_cookie"); // NOI18N
        jPanel1.add(txt_cookie);
        txt_cookie.setBounds(60, 50, 510, 20);

        jLabel12.setText("Bin path");
        jPanel1.add(jLabel12);
        jLabel12.setBounds(10, 70, 60, 25);

        txt_bin.setEditable(false);
        jPanel1.add(txt_bin);
        txt_bin.setBounds(70, 80, 470, 18);

        btn_select_bin.setText("...");
        btn_select_bin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_select_binActionPerformed(evt);
            }
        });
        jPanel1.add(btn_select_bin);
        btn_select_bin.setBounds(550, 80, 20, 20);

        jLabel14.setText("Command");
        jPanel1.add(jLabel14);
        jLabel14.setBounds(10, 110, 64, 15);

        txt_command.setEditable(false);
        jPanel1.add(txt_command);
        txt_command.setBounds(80, 110, 490, 19);

        btn_del.setText("Del");
        btn_del.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_delActionPerformed(evt);
            }
        });
        jPanel1.add(btn_del);
        btn_del.setBounds(440, 20, 60, 20);

        jPanel4.add(jPanel1);
        jPanel1.setBounds(0, 0, 580, 137);

        jPanel2.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jPanel2.setLayout(null);

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder("Custom options"));
        jPanel5.setLayout(null);

        jLabel2.setText("DBMS");
        jPanel5.add(jLabel2);
        jLabel2.setBounds(10, 20, 36, 15);

        cmb_dbms.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Auto", "MySQL", "Oracle", "PostgreSQL", "Microsoft SQL Server", "Microsoft Access", "SQLite", "Firebird", "Sybase", "SAP MaxDB", "DB2" }));
        cmb_dbms.setName("cmb_dbms"); // NOI18N
        cmb_dbms.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmb_dbmsItemStateChanged(evt);
            }
        });
        jPanel5.add(cmb_dbms);
        cmb_dbms.setBounds(50, 20, 170, 20);

        jLabel3.setText("Action");
        jPanel5.add(jLabel3);
        jLabel3.setBounds(10, 50, 40, 15);

        cmb_action.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Auto", "Enum DBMS users", "Enum DBMS users password hashes", "Enum DBMS users privileges", "Enum DBMS users roles", "Enum DBMS databases", "Enum DBMS database tables", "Enum DBMS database table columns", "Enum DBMS schema", "Dump DBMS database table entries", "Dump all DBMS databases tables entries" }));
        cmb_action.setName("cmb_Action"); // NOI18N
        cmb_action.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmb_actionItemStateChanged(evt);
            }
        });
        jPanel5.add(cmb_action);
        cmb_action.setBounds(60, 50, 160, 20);

        jLabel5.setText("Level");
        jPanel5.add(jLabel5);
        jLabel5.setBounds(10, 110, 32, 15);

        cmb_level.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "-", "1", "2", "3", "4", "5" }));
        cmb_level.setName("cmb_level"); // NOI18N
        cmb_level.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmb_levelItemStateChanged(evt);
            }
        });
        jPanel5.add(cmb_level);
        cmb_level.setBounds(60, 110, 36, 20);

        jLabel6.setText("Risk");
        jPanel5.add(jLabel6);
        jLabel6.setBounds(130, 110, 27, 15);

        cmb_risk.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "-", "1", "2", "3" }));
        cmb_risk.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmb_riskItemStateChanged(evt);
            }
        });
        cmb_risk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmb_riskActionPerformed(evt);
            }
        });
        jPanel5.add(cmb_risk);
        cmb_risk.setBounds(180, 110, 36, 20);

        jLabel4.setText("Entries for table(s)");
        jPanel5.add(jLabel4);
        jLabel4.setBounds(10, 80, 115, 15);

        txt_count.setName("txt_count"); // NOI18N
        txt_count.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_countKeyReleased(evt);
            }
        });
        jPanel5.add(txt_count);
        txt_count.setBounds(130, 80, 90, 19);

        chk_random_user_agent.setText("Random User-Agent?");
        chk_random_user_agent.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        chk_random_user_agent.setMargin(new java.awt.Insets(0, 0, 0, 0));
        chk_random_user_agent.setName("txt_useragent"); // NOI18N
        chk_random_user_agent.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_random_user_agentItemStateChanged(evt);
            }
        });
        jPanel5.add(chk_random_user_agent);
        chk_random_user_agent.setBounds(10, 150, 155, 20);

        chk_verbose.setText("Verbose?");
        chk_verbose.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        chk_verbose.setMargin(new java.awt.Insets(5, 0, 2, 0));
        chk_verbose.setName("txt_useragent"); // NOI18N
        chk_verbose.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_verboseItemStateChanged(evt);
            }
        });
        jPanel5.add(chk_verbose);
        chk_verbose.setBounds(10, 130, 77, 20);

        chk_fingerprint.setText("Fingerprint?");
        chk_fingerprint.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        chk_fingerprint.setMargin(new java.awt.Insets(5, 0, 0, 0));
        chk_fingerprint.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_fingerprintItemStateChanged(evt);
            }
        });
        jPanel5.add(chk_fingerprint);
        chk_fingerprint.setBounds(120, 130, 96, 20);

        jPanel2.add(jPanel5);
        jPanel5.setBounds(0, 0, 230, 180);

        jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder("Database"));
        jPanel6.setLayout(null);

        jLabel8.setText("DB to enum");
        jPanel6.add(jLabel8);
        jLabel8.setBounds(10, 20, 74, 15);

        jLabel9.setText("Table to enum");
        jPanel6.add(jLabel9);
        jLabel9.setBounds(10, 50, 90, 15);

        jLabel10.setText("Col to enum");
        jPanel6.add(jLabel10);
        jLabel10.setBounds(10, 80, 77, 15);

        jLabel11.setText("User to enum");
        jPanel6.add(jLabel11);
        jLabel11.setBounds(10, 110, 84, 15);

        txt_bbdd.setAlignmentY(0.0F);
        txt_bbdd.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_bbddKeyReleased(evt);
            }
        });
        jPanel6.add(txt_bbdd);
        txt_bbdd.setBounds(110, 20, 110, 20);

        txt_table.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_tableKeyReleased(evt);
            }
        });
        jPanel6.add(txt_table);
        txt_table.setBounds(110, 50, 110, 19);

        txt_column.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_columnKeyReleased(evt);
            }
        });
        jPanel6.add(txt_column);
        txt_column.setBounds(110, 80, 110, 20);

        txt_user.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_userKeyReleased(evt);
            }
        });
        jPanel6.add(txt_user);
        txt_user.setBounds(110, 110, 110, 20);

        jPanel2.add(jPanel6);
        jPanel6.setBounds(0, 180, 230, 140);

        jpn_tampers.setBorder(javax.swing.BorderFactory.createTitledBorder("Tampers"));
        jpn_tampers.setLayout(null);

        chk_ifnull2ifisnull.setText("ifnull2ifisnull");
        chk_ifnull2ifisnull.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_ifnull2ifisnull);
        chk_ifnull2ifisnull.setBounds(10, 180, 110, 23);

        chk_equaltolike.setText("equaltolike");
        chk_equaltolike.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_equaltolike);
        chk_equaltolike.setBounds(10, 160, 95, 23);

        chk_multiplespaces.setText("multiplespaces");
        chk_multiplespaces.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_multiplespaces);
        chk_multiplespaces.setBounds(10, 200, 119, 23);

        chk_apostrophemask.setText("apostrophemask");
        chk_apostrophemask.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_apostrophemask);
        chk_apostrophemask.setBounds(10, 20, 130, 23);

        chk_percentage.setText("percentage");
        chk_percentage.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_percentage);
        chk_percentage.setBounds(10, 220, 93, 23);

        chk_securesphere.setText("securesphere");
        chk_securesphere.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_securesphere);
        chk_securesphere.setBounds(10, 260, 107, 23);

        chk_randomcomments.setText("randomcomments");
        chk_randomcomments.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_randomcomments);
        chk_randomcomments.setBounds(140, 220, 138, 23);

        chk_space2randomblank.setText("space2randomblank");
        chk_space2randomblank.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2randomblank);
        chk_space2randomblank.setBounds(140, 180, 151, 23);

        chk_halfversionedmorekeywords.setText("halfversionedmorekeywords");
        chk_halfversionedmorekeywords.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_halfversionedmorekeywords);
        chk_halfversionedmorekeywords.setBounds(140, 20, 203, 23);

        chk_versionedkeywords.setText("versionedkeywords");
        chk_versionedkeywords.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_versionedkeywords);
        chk_versionedkeywords.setBounds(140, 200, 147, 23);

        chk_space2morehash.setText("space2morehash");
        chk_space2morehash.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2morehash);
        chk_space2morehash.setBounds(140, 240, 130, 23);

        chk_space2hash.setText("space2hash");
        chk_space2hash.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2hash);
        chk_space2hash.setBounds(10, 140, 98, 23);

        chk_appendnullbyte.setText("appendnullbyte");
        chk_appendnullbyte.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_appendnullbyte);
        chk_appendnullbyte.setBounds(10, 40, 122, 23);

        chk_base64encode.setText("base64encode");
        chk_base64encode.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_base64encode);
        chk_base64encode.setBounds(10, 60, 114, 23);

        chk_between.setText("between");
        chk_between.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_between);
        chk_between.setBounds(10, 80, 78, 23);

        chk_chardoubleencode.setText("chardoubleencode");
        chk_chardoubleencode.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_chardoubleencode);
        chk_chardoubleencode.setBounds(140, 280, 138, 23);

        chk_charencode.setText("charencode");
        chk_charencode.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_charencode);
        chk_charencode.setBounds(10, 120, 95, 23);

        chk_space2plus.setText("space2plus");
        chk_space2plus.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2plus);
        chk_space2plus.setBounds(10, 280, 95, 23);

        chk_modsecurityversioned.setText("modsecurityversioned");
        chk_modsecurityversioned.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_modsecurityversioned);
        chk_modsecurityversioned.setBounds(140, 40, 163, 23);

        chk_modsecurityzeroversioned.setText("modsecurityzeroversioned");
        chk_modsecurityzeroversioned.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_modsecurityzeroversioned);
        chk_modsecurityzeroversioned.setBounds(140, 60, 190, 23);

        chk_versionedmorekeywords.setText("versionedmorekeywords");
        chk_versionedmorekeywords.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_versionedmorekeywords);
        chk_versionedmorekeywords.setBounds(140, 80, 179, 23);

        chk_space2mssqlblank.setText("space2mssqlblank");
        chk_space2mssqlblank.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2mssqlblank);
        chk_space2mssqlblank.setBounds(140, 100, 141, 23);

        chk_space2mssqlhash.setText("space2mssqlhash");
        chk_space2mssqlhash.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2mssqlhash);
        chk_space2mssqlhash.setBounds(140, 120, 136, 23);

        chk_space2mysqlblank.setText("space2mysqlblank");
        chk_space2mysqlblank.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2mysqlblank);
        chk_space2mysqlblank.setBounds(140, 140, 141, 23);

        chk_space2mysqldash.setText("space2mysqldash");
        chk_space2mysqldash.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2mysqldash);
        chk_space2mysqldash.setBounds(140, 160, 136, 23);

        chk_charunicodeencode.setText("charunicodeencode");
        chk_charunicodeencode.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_charunicodeencode);
        chk_charunicodeencode.setBounds(140, 260, 144, 23);

        chk_space2dash.setText("space2dash");
        chk_space2dash.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_space2dash);
        chk_space2dash.setBounds(10, 100, 98, 23);

        chk_unmagicquotes.setText("unmagicquotes");
        chk_unmagicquotes.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_charencodeItemStateChanged(evt);
            }
        });
        jpn_tampers.add(chk_unmagicquotes);
        chk_unmagicquotes.setBounds(10, 240, 121, 23);

        jPanel2.add(jpn_tampers);
        jpn_tampers.setBounds(230, 0, 350, 320);

        jPanel4.add(jPanel2);
        jPanel2.setBounds(0, 133, 580, 320);

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Parameters to test"));
        jPanel3.setLayout(null);

        lst_params.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { " " };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        lst_params.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lst_paramsMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(lst_params);

        jPanel3.add(jScrollPane1);
        jScrollPane1.setBounds(5, 16, 300, 100);

        jLabel15.setFont(new java.awt.Font("Dialog", 0, 9));
        jLabel15.setText("You can edit paraemters with double mouse clicking");
        jPanel3.add(jLabel15);
        jLabel15.setBounds(10, 120, 280, 10);

        jPanel4.add(jPanel3);
        jPanel3.setBounds(270, 450, 310, 140);

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder("Optimization"));
        jPanel7.setLayout(null);

        chk_optimization_all.setText("Turn on all optimization switches ");
        chk_optimization_all.setAlignmentY(0.0F);
        chk_optimization_all.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        chk_optimization_all.setMargin(new java.awt.Insets(2, 0, 2, 2));
        chk_optimization_all.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_optimization_allItemStateChanged(evt);
            }
        });
        jPanel7.add(chk_optimization_all);
        chk_optimization_all.setBounds(10, 20, 238, 23);

        chk_optimization_predict.setText("Predict common queries output");
        chk_optimization_predict.setAlignmentY(0.0F);
        chk_optimization_predict.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        chk_optimization_predict.setMargin(new java.awt.Insets(2, 0, 2, 2));
        chk_optimization_predict.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_optimization_persistentItemStateChanged(evt);
            }
        });
        chk_optimization_predict.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk_optimization_predictActionPerformed(evt);
            }
        });
        jPanel7.add(chk_optimization_predict);
        chk_optimization_predict.setBounds(10, 40, 219, 23);

        chk_optimization_persistent.setText("Use persistent HTTP(s) connections ");
        chk_optimization_persistent.setAlignmentY(0.0F);
        chk_optimization_persistent.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        chk_optimization_persistent.setMargin(new java.awt.Insets(2, 0, 2, 2));
        chk_optimization_persistent.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_optimization_persistentItemStateChanged(evt);
            }
        });
        jPanel7.add(chk_optimization_persistent);
        chk_optimization_persistent.setBounds(10, 60, 247, 23);

        chk_optimization_page_lenth.setText("Get page length without actual body");
        chk_optimization_page_lenth.setAlignmentY(0.0F);
        chk_optimization_page_lenth.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        chk_optimization_page_lenth.setMargin(new java.awt.Insets(2, 0, 2, 2));
        chk_optimization_page_lenth.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                chk_optimization_persistentItemStateChanged(evt);
            }
        });
        chk_optimization_page_lenth.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk_optimization_page_lenthActionPerformed(evt);
            }
        });
        jPanel7.add(chk_optimization_page_lenth);
        chk_optimization_page_lenth.setBounds(10, 80, 251, 23);

        jLabel13.setText("Threads");
        jPanel7.add(jLabel13);
        jLabel13.setBounds(10, 110, 50, 15);

        txt_optimization_threads.setText("1");
        txt_optimization_threads.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txt_optimization_threadsKeyReleased(evt);
            }
        });
        jPanel7.add(txt_optimization_threads);
        txt_optimization_threads.setBounds(70, 110, 57, 19);

        chk_debug.setText("Debug");
        chk_debug.setMargin(new java.awt.Insets(0, 0, 0, 0));
        jPanel7.add(chk_debug);
        chk_debug.setBounds(190, 110, 70, 19);

        jPanel4.add(jPanel7);
        jPanel7.setBounds(0, 450, 270, 140);

        bnt_run.setText("Run");
        bnt_run.setName("cmd_run"); // NOI18N
        bnt_run.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                bnt_runMouseClicked(evt);
            }
        });
        jPanel4.add(bnt_run);
        bnt_run.setBounds(520, 600, 58, 25);

        btn_cancel.setText("Exit");
        btn_cancel.setName("cmd_cancel"); // NOI18N
        btn_cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_cancelActionPerformed(evt);
            }
        });
        jPanel4.add(btn_cancel);
        btn_cancel.setBounds(450, 600, 57, 25);

        jButton1.setText("Help");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        jPanel4.add(jButton1);
        jButton1.setBounds(10, 600, 62, 25);

        tbl_main.addTab("SQLMap options", jPanel4);

        jScrollPane2.setViewportView(tbl_main);

        getContentPane().add(jScrollPane2);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void cmb_urlsItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmb_urlsItemStateChanged
        try {
            if(evt.getItem() != null)
            {
                this.configureGUI(evt.getItem().toString());
            }
        } catch (Exception ex) {
            Logger.getLogger(sqlmapGUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_cmb_urlsItemStateChanged

    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        // Stop all threads
//        for(int i = 0; i < this.tabs.size(); i++)
//        {
//            // Close tabs
//            Thread t = this.tabs.get(i);
//            t.interrupt();
//            this.tbl_main.removeAll();
//        }
//
//        this.cmb_urls.setModel(new DefaultComboBoxModel());
    }//GEN-LAST:event_formWindowClosing

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        JOptionPane.showMessageDialog(this, "This plugin was developed by Daniel García (cr0hn) - dani@iniqua.com | @ggdaniel\n\nLinkedin: http://es.linkedin.com/in/garciagarciadaniel\nProject page: http://code.google.com/p/gason/\nDoc: http://blog.buguroo.com/?p=2471", "Help", JOptionPane.INFORMATION_MESSAGE);
}//GEN-LAST:event_jButton1ActionPerformed

    private void btn_cancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_cancelActionPerformed
        // Stop all threads
        for(int i = 0; i < this.tabs.size(); i++) {
            Thread t = this.tabs.get(i);
            t.interrupt();
        }

        this.setVisible(false);
}//GEN-LAST:event_btn_cancelActionPerformed

    private void txt_optimization_threadsKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_optimization_threadsKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_optimization_threadsKeyReleased

    private void chk_optimization_page_lenthActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chk_optimization_page_lenthActionPerformed
        // TODO add your handling code here:
}//GEN-LAST:event_chk_optimization_page_lenthActionPerformed

    private void chk_optimization_persistentItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_optimization_persistentItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_optimization_persistentItemStateChanged

    private void chk_optimization_predictActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chk_optimization_predictActionPerformed
        // TODO add your handling code here:
}//GEN-LAST:event_chk_optimization_predictActionPerformed

    private void chk_optimization_allItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_optimization_allItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_optimization_allItemStateChanged

    private void lst_paramsMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lst_paramsMouseClicked
        if(evt.getClickCount() == 2 && !evt.isConsumed()) {
            evt.consume();

            String p = lst_params.getSelectedValue().toString();
            int index = lst_params.getSelectedIndex();
            
            if(p != null && !p.isEmpty()) {
                // Get param name and value
                String p_splited[] = p.split("=");
                String p_name = "";
                String p_value = "";
                if(p_splited.length > 0)
                    p_name = p_splited[0];
                if(p_splited.length > 1)
                    p_value = p_splited[1];

                // Show dialog
                Dialog_param _editor = new Dialog_param(p_name, p_value, this, true);
                _editor.setVisible(true);
                // Get modified fields
                p_name = _editor.param_name;
                p_value = _editor.param_value;
                
                // Modify selected value
                DefaultComboBoxModel m = ((DefaultComboBoxModel) lst_params.getModel());
                m.removeElementAt(lst_params.getSelectedIndex());
                //m.addElement((Object)(p_name + "=" + p_value));
                m.insertElementAt((Object)(p_name + "=" + p_value), index);

            }
        } else {
            txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
        }
}//GEN-LAST:event_lst_paramsMouseClicked

    private void chk_charencodeItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_charencodeItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_charencodeItemStateChanged

    private void txt_userKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_userKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_userKeyReleased

    private void txt_columnKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_columnKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_columnKeyReleased

    private void txt_tableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_tableKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_tableKeyReleased

    private void txt_bbddKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_bbddKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_bbddKeyReleased

    private void chk_fingerprintItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_fingerprintItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_fingerprintItemStateChanged

    private void chk_verboseItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_verboseItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_verboseItemStateChanged

    private void chk_random_user_agentItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_chk_random_user_agentItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_chk_random_user_agentItemStateChanged

    private void txt_countKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txt_countKeyReleased
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_txt_countKeyReleased

    private void cmb_riskItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmb_riskItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_cmb_riskItemStateChanged

    private void cmb_levelItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmb_levelItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_cmb_levelItemStateChanged

    private void cmb_actionItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmb_actionItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_cmb_actionItemStateChanged

    private void cmb_dbmsItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmb_dbmsItemStateChanged
        txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
}//GEN-LAST:event_cmb_dbmsItemStateChanged

    private void btn_delActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_delActionPerformed
        if(cmb_urls.getItemCount() > 0) {
            try {

                cmb_action.setEnabled(true);
                this.URLs.remove(cmb_urls.getSelectedIndex());
                cmb_urls.removeItemAt(cmb_urls.getSelectedIndex());

                if(cmb_urls.getItemCount() > 0)
                    this.configureGUI(cmb_urls.getSelectedItem().toString());
            } catch (Exception ex) {
                Logger.getLogger(sqlmapGUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else{
            cmb_action.setEnabled(false);
        }
}//GEN-LAST:event_btn_delActionPerformed

    private void btn_select_binActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_select_binActionPerformed
        JFileChooser jfc = new JFileChooser();
        int ret = jfc.showOpenDialog(this);
        if(ret == JFileChooser.APPROVE_OPTION) {
            sqlmapGUI.command = jfc.getSelectedFile().getAbsolutePath();
            txt_bin.setText(sqlmapGUI.command);
            bnt_run.setEnabled(true);
            txt_command.setText(this.GetCommandString(cmb_urls.getSelectedItem().toString()));
            txt_bin.setForeground(Color.black);
        }
}//GEN-LAST:event_btn_select_binActionPerformed

    private void cmb_urlsPropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_cmb_urlsPropertyChange

}//GEN-LAST:event_cmb_urlsPropertyChange

    private void cmb_riskActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmb_riskActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_cmb_riskActionPerformed

    private void bnt_runMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_bnt_runMouseClicked
        this.Execute(this.cmb_urls.getSelectedItem().toString());
    }//GEN-LAST:event_bnt_runMouseClicked

    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bnt_run;
    private javax.swing.JButton btn_cancel;
    private javax.swing.JButton btn_del;
    private javax.swing.JButton btn_select_bin;
    private javax.swing.JCheckBox chk_apostrophemask;
    private javax.swing.JCheckBox chk_appendnullbyte;
    private javax.swing.JCheckBox chk_base64encode;
    private javax.swing.JCheckBox chk_between;
    private javax.swing.JCheckBox chk_chardoubleencode;
    private javax.swing.JCheckBox chk_charencode;
    private javax.swing.JCheckBox chk_charunicodeencode;
    private javax.swing.JCheckBox chk_debug;
    private javax.swing.JCheckBox chk_equaltolike;
    private javax.swing.JCheckBox chk_fingerprint;
    private javax.swing.JCheckBox chk_halfversionedmorekeywords;
    private javax.swing.JCheckBox chk_ifnull2ifisnull;
    private javax.swing.JCheckBox chk_modsecurityversioned;
    private javax.swing.JCheckBox chk_modsecurityzeroversioned;
    private javax.swing.JCheckBox chk_multiplespaces;
    private javax.swing.JCheckBox chk_optimization_all;
    private javax.swing.JCheckBox chk_optimization_page_lenth;
    private javax.swing.JCheckBox chk_optimization_persistent;
    private javax.swing.JCheckBox chk_optimization_predict;
    private javax.swing.JCheckBox chk_percentage;
    private javax.swing.JCheckBox chk_random_user_agent;
    private javax.swing.JCheckBox chk_randomcomments;
    private javax.swing.JCheckBox chk_securesphere;
    private javax.swing.JCheckBox chk_space2dash;
    private javax.swing.JCheckBox chk_space2hash;
    private javax.swing.JCheckBox chk_space2morehash;
    private javax.swing.JCheckBox chk_space2mssqlblank;
    private javax.swing.JCheckBox chk_space2mssqlhash;
    private javax.swing.JCheckBox chk_space2mysqlblank;
    private javax.swing.JCheckBox chk_space2mysqldash;
    private javax.swing.JCheckBox chk_space2plus;
    private javax.swing.JCheckBox chk_space2randomblank;
    private javax.swing.JCheckBox chk_unmagicquotes;
    private javax.swing.JCheckBox chk_verbose;
    private javax.swing.JCheckBox chk_versionedkeywords;
    private javax.swing.JCheckBox chk_versionedmorekeywords;
    private javax.swing.JComboBox cmb_action;
    private javax.swing.JComboBox cmb_dbms;
    private javax.swing.JComboBox cmb_level;
    private javax.swing.JComboBox cmb_method;
    private javax.swing.JComboBox cmb_risk;
    private javax.swing.JComboBox cmb_urls;
    private javax.swing.JButton jButton1;
    private javax.swing.JDialog jDialog1;
    private javax.swing.JDialog jDialog2;
    private javax.swing.JDialog jDialog3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JPanel jpn_tampers;
    private javax.swing.JList lst_params;
    private javax.swing.JTabbedPane tbl_main;
    private javax.swing.JTextField txt_bbdd;
    private javax.swing.JTextField txt_bin;
    private javax.swing.JTextField txt_column;
    private javax.swing.JTextField txt_command;
    private javax.swing.JTextField txt_cookie;
    private javax.swing.JTextField txt_count;
    private javax.swing.JTextField txt_optimization_threads;
    private javax.swing.JTextField txt_table;
    private javax.swing.JTextField txt_user;
    // End of variables declaration//GEN-END:variables

}
