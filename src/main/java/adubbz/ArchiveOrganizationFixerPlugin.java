package main.java.adubbz;

import java.lang.reflect.Field;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.CODE_VIEWER,
        shortDescription = "Data organization fixer",
        description = "Fixes the DataOrganization for archives."
    )
public class ArchiveOrganizationFixerPlugin extends ProgramPlugin {

    public ArchiveOrganizationFixerPlugin(PluginTool tool) {
        super(tool, false, false);
    }

    @Override
    protected void programOpened(Program program) {
        DataTypeManagerService dtmService = this.tool.getService(DataTypeManagerService.class);
        
        for (DataTypeManager dtm : dtmService.getDataTypeManagers()) {
            try {
                Field dataOrganizationField = ReflectionUtilities.locateFieldObjectOnClass("dataOrganization", DataTypeManagerDB.class);
                dataOrganizationField.setAccessible(true);
                dataOrganizationField.set(dtm, DataOrganizationImpl.getDefaultOrganization(program.getLanguage()));
            } catch (IllegalArgumentException | IllegalAccessException e) {
                Msg.error(this, "Failed to locate dataOrganization field", e);
            }
        }
    }
    
}
