package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.gui.Config;
import burp.gui.InteractshTab;
import interactsh.InteractshEntry;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender
		implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
	public static MontoyaApi api;
	public static InteractshTab tab;
	public static volatile boolean unloading = false;

	@Override
	public void initialize(MontoyaApi api) {
		BurpExtender.unloading = false;
		BurpExtender.api = api;

		api.extension().setName("Interactsh Collaborator");
		api.userInterface().registerContextMenuItemsProvider(this);
		api.extension().registerUnloadingHandler(this);
		api.logging().logToOutput("Starting Interactsh Collaborator");

		burp.gui.Config.generateConfig();
		BurpExtender.tab = new InteractshTab(api);
		burp.gui.Config.loadConfig();

		api.userInterface().registerSuiteTab("Interactsh", tab);
	}

	@Override
	public void extensionUnloaded() {
		BurpExtender.unloading = true;
		if (BurpExtender.tab != null) {
			BurpExtender.tab.cleanup();
		}
		if (BurpExtender.api != null) {
			try {
				BurpExtender.api.logging().logToOutput("Thanks for collaborating!");
			} catch (Exception ignored) {
			}
		}
		BurpExtender.api = null;
		BurpExtender.tab = null;
	}

	public static int getPollTime() {
		try {
			return Integer.parseInt(BurpExtender.tab.getPollField().getText());
		} catch (Exception ex) {
		}
		return Integer.parseInt(Config.getPollInterval());
	}

	public static void addToTable(InteractshEntry i) {
		BurpExtender.tab.addToTable(i);
	}

	public static void debugLog(String message) {
		if (api != null && !unloading && burp.gui.Config.isDebugEnabled()) {
			api.logging().logToOutput(message);
		}
	}

	@Override
	public List<Component> provideMenuItems(ContextMenuEvent event) {
		List<Component> menuList = new ArrayList<Component>();
		JMenuItem item = new JMenuItem("Copy Interactsh URL");
		item.addActionListener(e -> BurpExtender.tab.getListener().copyCurrentUrlToClipboard());
		menuList.add(item);

		return menuList;
	}
}
