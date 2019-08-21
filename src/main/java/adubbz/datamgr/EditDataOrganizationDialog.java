package main.java.adubbz.datamgr;

import java.awt.BorderLayout;

import javax.swing.JPanel;

import docking.DialogComponentProvider;
import ghidra.program.model.data.DataOrganizationImpl;

public class EditDataOrganizationDialog extends DialogComponentProvider {
    
    private DataOrganizationImpl dataOrganization;
    
    private JPanel mainPanel;
    private ExtendedDataOrganizationPanel organizationPanel;
    
    public EditDataOrganizationDialog(DataOrganizationImpl dataOrganization, String title) {
        super(title);
        this.dataOrganization = dataOrganization;
        this.organizationPanel = new ExtendedDataOrganizationPanel();
        this.organizationPanel.setOrganization(dataOrganization);
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(this.organizationPanel, BorderLayout.CENTER);
        addWorkPanel(mainPanel);
        initialize();
    }

    private void initialize() {
        addOKButton();
        addCancelButton();
    }   
    
    @Override
    protected void okCallback() {
        close();
    }

    @Override
    protected void cancelCallback() {
        close();
    }
}