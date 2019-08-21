package main.java.adubbz.datamgr;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.lang.reflect.Field;

import javax.swing.JLabel;
import javax.swing.JTextField;

import ghidra.app.plugin.core.datamgr.DataOrganizationPanel;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

public class ExtendedDataOrganizationPanel extends DataOrganizationPanel {
    JTextField pointerSizeComponent;

    public ExtendedDataOrganizationPanel() {
        setUpPointerSize();

        remove(getComponentCount() - 1);
        remove(getComponentCount() - 1);
        add(new JLabel("Pointer Size"));
        add(pointerSizeComponent);
        add(new JLabel(""));
        add(new JLabel(""));
    }

    @Override
    public void setOrganization(DataOrganizationImpl dataOrganization) {
        super.setOrganization(dataOrganization);

        int pointerSize = dataOrganization.getPointerSize();
        pointerSizeComponent.setText(Integer.toString(pointerSize));
    }

    private void setUpPointerSize() {
        pointerSizeComponent = new JTextField(3);
        pointerSizeComponent.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updatedPointerSize();
            }
        });
        pointerSizeComponent.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                // TODO
            }

            @Override
            public void focusLost(FocusEvent e) {
                updatedPointerSize();
            }
        });
    }
    
    protected void updatedPointerSize() {
        int pointerSize = Integer.decode(pointerSizeComponent.getText()).intValue();
        
        try {
            Field dataOrganizationField = ReflectionUtilities.locateFieldObjectOnClass("dataOrganization", DataOrganizationPanel.class);
            dataOrganizationField.setAccessible(true);
            DataOrganizationImpl dataOrganization = (DataOrganizationImpl)dataOrganizationField.get(this);
            dataOrganization.setPointerSize(pointerSize);
        } catch (IllegalArgumentException | IllegalAccessException e) {
            Msg.error(this, "Failed to locate dataOrganization field", e);
        }
    }
}
