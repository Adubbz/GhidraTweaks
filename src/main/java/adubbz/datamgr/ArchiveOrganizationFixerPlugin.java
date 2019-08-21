package main.java.adubbz.datamgr;

import java.lang.reflect.Field;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ArchiveManagerListener;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
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
        description = "Fixes the DataOrganization for archives.",
        servicesRequired = { DataTypeManagerService.class }
        )
public class ArchiveOrganizationFixerPlugin extends ProgramPlugin {

    public ArchiveOrganizationFixerPlugin(PluginTool tool) {
        super(tool, false, false);
    }

    @Override
    protected void init() {
        /* The plugin is what implements the service. Yay for hax */
        DataTypeManagerPlugin dtmPlugin = (DataTypeManagerPlugin)((Object)this.tool.getService(DataTypeManagerService.class));

        // Add our custom actions
        this.tool.addLocalAction(dtmPlugin.getProvider(), new EditDataOrganizationAction(dtmPlugin));
        
        dtmPlugin.getDataTypeManagerHandler().addArchiveManagerListener(new ArchiveManagerListener() {
            @Override
            public void archiveOpened(Archive archive) {
                Program program = ArchiveOrganizationFixerPlugin.this.currentProgram;

                if (program == null) {
                    return;
                }

                fixDataOrganization(program, archive.getDataTypeManager());
            }

            @Override
            public void archiveClosed(Archive archive) {
            }

            @Override
            public void archiveStateChanged(Archive archive) {
            }

            @Override
            public void archiveDataTypeManagerChanged(Archive archive) {
            }

        });
    }

    @Override
    protected void programOpened(Program program) {
        DataTypeManagerService dtmService = this.tool.getService(DataTypeManagerService.class);

        for (DataTypeManager dtm : dtmService.getDataTypeManagers()) {
            fixDataOrganization(program, dtm);
        }
    }

    private void fixDataOrganization(Program program, DataTypeManager dtm) {
        try {
            Field dataOrganizationField = ReflectionUtilities.locateFieldObjectOnClass("dataOrganization", DataTypeManagerDB.class);
            dataOrganizationField.setAccessible(true);
            dataOrganizationField.set(dtm, DataOrganizationImpl.getDefaultOrganization(program.getLanguage()));
            Msg.info(this, "Adjusted pointer size for " + dtm.getName() + " to " + program.getLanguage().getDefaultSpace().getPointerSize());
        } catch (IllegalArgumentException | IllegalAccessException e) {
            Msg.error(this, "Failed to locate dataOrganization field", e);
        }
    }

}
