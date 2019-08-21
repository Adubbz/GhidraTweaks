package main.java.adubbz.datamgr;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeState;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.FileArchiveNode;
import ghidra.program.model.data.DataOrganizationImpl;

public class EditDataOrganizationAction extends DockingAction  {
    public static final String MENU_NAME = "Edit Data Organization";
    
    private final DataTypeManagerPlugin plugin;
    
    public EditDataOrganizationAction(DataTypeManagerPlugin plugin) {
        super("Edit Data Organization", plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] { MENU_NAME }, null, "FileEdit"));
    }

    @Override
    public void actionPerformed(ActionContext context) {
        GTree gTree = (GTree) context.getContextObject();

        TreePath[] selectionPaths = gTree.getSelectionPaths();
        GTreeState treeState = gTree.getTreeState();

        DataTypeEditorManager editorManager = plugin.getEditorManager();
        for (TreePath path : selectionPaths) {
            FileArchiveNode node = (FileArchiveNode) path.getLastPathComponent();
            FileArchive archive = (FileArchive) node.getArchive();
            
            EditDataOrganizationDialog dialog = new EditDataOrganizationDialog((DataOrganizationImpl)archive.getDataTypeManager().getDataOrganization(), "Data Organization");
            plugin.getTool().showDialog(dialog);
        }
        gTree.restoreTreeState(treeState);
    }
}