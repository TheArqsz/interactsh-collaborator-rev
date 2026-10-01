package burp.gui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SpringLayout;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.gui.ToastNotification.MessageType;
import burp.listeners.InteractshListener;
import interactsh.InteractshClient;
import interactsh.InteractshEntry;
import layout.SpringUtilities;
import lombok.Getter;

public class InteractshTab extends JComponent {
	private final MontoyaApi api;

	private JTabbedPane mainPane;
	private JSplitPane splitPane;
	private JScrollPane scrollPane;
	private JSplitPane tableSplitPane;
	private JPanel resultsPanel;
	@Getter
	private JTextField pollField;

	private Table logTable;
	private final LogTable logTableModel;

	private static JTextField serverText;
	private static JTextField portText;
	private static JTextField authText;
	private static JTextField pollText;
	private static JCheckBox tlsBox;
	private static JComboBox<String> aesModeBox;
	private static JCheckBox debugLoggingBox;
	private static JCheckBox hideSharedBox;
	private static JCheckBox hideWildcardBox;
	private static JTextField cidLengthText;
	private static JTextField cidNonceLengthText;

	private TableRowSorter<TableModel> sorter;
	private String selectedProtocol = "All";

	private final List<InteractshEntry> log = new ArrayList<>();
	private InteractshListener listener;

	private HttpRequestEditor requestViewer;
	private HttpResponseEditor responseViewer;

	private JPanel resultsCardPanel;
	private CardLayout resultsLayout;
	private JTextArea genericDetailsViewer;

	public InteractshTab(MontoyaApi api) {
		this.api = api;
		this.listener = new InteractshListener(
				newUrl -> ToastNotification.showToast("✓ Interactsh session ready.", MessageType.SUCCESS),
				errorMsg -> ToastNotification.showToast("❌ " + errorMsg, MessageType.ERROR));

		setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

		mainPane = new JTabbedPane();
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		mainPane.addTab("Logs", splitPane);

		requestViewer = api.userInterface().createHttpRequestEditor();
		responseViewer = api.userInterface().createHttpResponseEditor();
		JSplitPane viewersSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				requestViewer.uiComponent(), responseViewer.uiComponent());
		viewersSplitPane.setResizeWeight(0.5);

		resultsPanel = new JPanel(new BorderLayout());
		genericDetailsViewer = new JTextArea();
		genericDetailsViewer.setEditable(false);
		genericDetailsViewer.setWrapStyleWord(true);
		genericDetailsViewer.setLineWrap(true);
		resultsPanel.add(new JScrollPane(genericDetailsViewer), BorderLayout.CENTER);

		resultsLayout = new CardLayout();
		resultsCardPanel = new JPanel(resultsLayout);
		resultsCardPanel.add(resultsPanel, "GENERIC_VIEW");
		resultsCardPanel.add(viewersSplitPane, "HTTP_VIEW");

		logTableModel = new LogTable();
		logTable = new Table(logTableModel);
		tableSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

		sorter = new TableRowSorter<>(logTableModel);
		logTable.setRowSorter(sorter);
		applyRowFilter();

		List<RowSorter.SortKey> sortKeys = new ArrayList<>();
		sortKeys.add(new RowSorter.SortKey(LogTable.Column.ID.ordinal(), SortOrder.DESCENDING));
		sorter.setSortKeys(sortKeys);

		sorter.setComparator(LogTable.Column.TYPE.ordinal(), Comparator.naturalOrder());
		sorter.setComparator(LogTable.Column.TIME.ordinal(), Comparator.naturalOrder());

		JTableHeader header = logTable.getTableHeader();
		((DefaultTableCellRenderer) header.getDefaultRenderer())
				.setHorizontalAlignment(SwingConstants.LEFT);

		for (LogTable.Column col : LogTable.Column.values()) {
			TableColumn tableColumn = logTable.getColumnModel().getColumn(col.ordinal());
			tableColumn.setPreferredWidth(col.getPreferredWidth());
			if (col.getMaxWidth() != -1) {
				tableColumn.setMaxWidth(col.getMaxWidth());
			}
		}

		LogTableCellRenderer renderer = new LogTableCellRenderer();
		for (int i = 0; i < logTable.getColumnCount(); i++) {
			logTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
		}

		logTable.setRowSelectionAllowed(true);
		logTable.setColumnSelectionAllowed(true);
		scrollPane = new JScrollPane(logTable);

		tableSplitPane.setTopComponent(scrollPane);
		tableSplitPane.setBottomComponent(resultsCardPanel);
		splitPane.setBottomComponent(tableSplitPane);

		JPanel mainTopPanel = new JPanel();
		mainTopPanel.setLayout(new BoxLayout(mainTopPanel, BoxLayout.Y_AXIS));
		mainTopPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JButton generateUrlButton = new JButton("Regenerate Interactsh Session");
		// Paint the background ourselves so the look and feel's hover state cannot
		// replace the custom colour.
		JButton copyUrlButton = new JButton("Copy URL to clipboard") {
			@Override
			protected void paintComponent(java.awt.Graphics g) {
				g.setColor(getBackground());
				g.fillRect(0, 0, getWidth(), getHeight());
				super.paintComponent(g);
			}
		};
		JButton refreshButton = new JButton("Refresh");
		JButton clearLogButton = new JButton("Clear log");
		JLabel pollLabel = new JLabel("Poll Time: ");
		pollField = new JTextField(Config.getPollInterval(), 4);
		pollField.setEditable(false);
		pollField.setOpaque(false);
		pollField.setBorder(null);
		pollField.setForeground(UIManager.getColor("Label.foreground"));

		Color copyButtonColor = new Color(216, 102, 51);
		Color copyButtonHoverColor = new Color(190, 82, 35);
		copyUrlButton.setBackground(copyButtonColor);
		copyUrlButton.setForeground(Color.WHITE);
		copyUrlButton.setContentAreaFilled(false);
		copyUrlButton.setOpaque(false);
		copyUrlButton.setFont(copyUrlButton.getFont().deriveFont(Font.BOLD));
		copyUrlButton.setBorderPainted(false);
		copyUrlButton.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseEntered(java.awt.event.MouseEvent e) {
				copyUrlButton.setBackground(copyButtonHoverColor);
			}

			@Override
			public void mouseExited(java.awt.event.MouseEvent e) {
				copyUrlButton.setBackground(copyButtonColor);
			}
		});

		generateUrlButton.addActionListener(e -> {
			listener.close();
			listener = new InteractshListener(
					newUrl -> {
						StringSelection stringSelection = new StringSelection(newUrl);
						try {
							Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
						} catch (Exception ex) {
						}
						try {
							java.awt.datatransfer.Clipboard sel = Toolkit.getDefaultToolkit().getSystemSelection();
							if (sel != null)
								sel.setContents(stringSelection, null);
						} catch (Exception ex) {
						}
						ToastNotification.showToast("✓ Regenerated and copied new Interact.sh URL.",
								MessageType.SUCCESS);
					},
					errorMsg -> ToastNotification.showToast("❌ " + errorMsg, MessageType.ERROR));
		});
		copyUrlButton.addActionListener(e -> {
			if (this.listener.copyCurrentUrlToClipboard()) {
				ToastNotification.showToast("URL copied to clipboard.", MessageType.INFO);
			} else {
				ToastNotification.showToast("❌ Failed to copy. Client not ready or registered.",
						MessageType.ERROR);
			}
		});
		refreshButton.addActionListener(e -> {
			boolean hasSession = this.listener.pollNowAll(polled -> {
				if (polled) {
					ToastNotification.showToast("Session refreshed.", MessageType.INFO);
				} else {
					ToastNotification.showToast("❌ Refresh failed. See the extension's error log.", MessageType.ERROR);
				}
			});
			if (!hasSession) {
				ToastNotification.showToast("❌ Failed to refresh. No active session.", MessageType.ERROR);
			}
		});
		clearLogButton.addActionListener(e -> this.clearLog());

		controlsPanel.add(generateUrlButton);
		controlsPanel.add(Box.createHorizontalStrut(3));
		controlsPanel.add(copyUrlButton);
		controlsPanel.add(Box.createHorizontalStrut(15));
		controlsPanel.add(refreshButton);
		controlsPanel.add(Box.createHorizontalStrut(3));
		controlsPanel.add(clearLogButton);
		controlsPanel.add(Box.createHorizontalStrut(20));
		controlsPanel.add(pollLabel);
		controlsPanel.add(pollField);

		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel filterLabel = new JLabel("Filter:");
		filterLabel.setEnabled(false);
		filterPanel.add(filterLabel);
		ButtonGroup filterGroup = new ButtonGroup();
		String[] protocols = { "All", "HTTP", "DNS", "SMTP", "LDAP", "SMB", "Responder", "FTP" };

		for (String protocol : protocols) {
			JToggleButton filterButton = new JToggleButton(protocol);
			filterButton.addActionListener(e -> {
				selectedProtocol = filterButton.getText();
				applyRowFilter();
			});

			filterGroup.add(filterButton);
			filterPanel.add(filterButton);

			if ("All".equals(protocol)) {
				filterButton.setSelected(true);
			}
		}

		mainTopPanel.add(controlsPanel);
		mainTopPanel.add(filterPanel);
		splitPane.setTopComponent(mainTopPanel);

		JPanel configPanel = new JPanel();
		configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));
		JPanel subConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		mainPane.addTab("Configuration", configPanel);
		configPanel.add(subConfigPanel);
		JPanel innerConfig = new JPanel();
		subConfigPanel.setMaximumSize(new Dimension(configPanel.getMaximumSize().width, 540));
		innerConfig.setLayout(new SpringLayout());
		subConfigPanel.add(innerConfig);

		String restartNote = " Changing this starts a new session.";
		serverText = new JTextField(Config.getHost(), 20);
		portText = new JTextField(Config.getPort(), 20);
		authText = new JTextField(Config.getAuth(), 20);
		pollText = new JTextField(Config.getPollInterval(), 20);
		tlsBox = new JCheckBox("", true);
		tlsBox.setSelected(Config.getScheme());
		aesModeBox = new JComboBox<>(new String[] { "AUTO", "CTR", "CFB" });
		aesModeBox.setSelectedItem(Config.getAesMode());
		debugLoggingBox = new JCheckBox("", false);
		debugLoggingBox.setSelected(Config.isDebugEnabled());
		hideSharedBox = new JCheckBox("", true);
		hideSharedBox.setSelected(Config.isHideShared());
		hideWildcardBox = new JCheckBox("", false);
		hideWildcardBox.setSelected(Config.isHideWildcard());
		cidLengthText = new JTextField(String.valueOf(Config.getCidLength()), 20);
		cidNonceLengthText = new JTextField(String.valueOf(Config.getCidNonceLength()), 20);

		addConfigHeading(innerConfig, "Server");
		addConfigRow(innerConfig, "Server: ", serverText,
				"Hostname of the interactsh server, without scheme or port." + restartNote);
		addConfigRow(innerConfig, "Port: ", portText,
				"Port of the server's HTTP(S) API, usually 443 with TLS and 80 without." + restartNote);
		addConfigRow(innerConfig, "TLS: ", tlsBox, "Connect to the server over HTTPS." + restartNote);
		addConfigRow(innerConfig, "Token: ", authText,
				"Token for servers started with -auth or -token. Leave empty for public servers." + restartNote);

		addConfigHeading(innerConfig, "Server compatibility");
		addConfigRow(innerConfig, "Correlation ID length: ", cidLengthText,
				"Must match the server's -cidl value (default 20)." + restartNote);
		addConfigRow(innerConfig, "Nonce length: ", cidNonceLengthText,
				"Must match the server's -cidn value (default 13)." + restartNote);
		addConfigRow(innerConfig, "AES Mode: ", aesModeBox,
				"Cipher mode used to decrypt interactions. AUTO tries CTR (current servers) and then CFB (older "
						+ "self-hosted servers).");

		addConfigHeading(innerConfig, "Polling");
		addConfigRow(innerConfig, "Poll Interval (sec): ", pollText,
				"Seconds between automatic polls. The Refresh button polls immediately.");

		addConfigHeading(innerConfig, "Display");
		addConfigRow(innerConfig, "Hide shared interactions: ", hideSharedBox,
				"Hide interactions the server cannot tie to a session (FTP, SMB, Responder, "
						+ "LDAP full logging). Token-authenticated servers send these to every client.");
		addConfigRow(innerConfig, "Hide wildcard interactions: ", hideWildcardBox,
				"Hide interactions with the server's root domain that do not belong to this "
						+ "session. Servers started with -wildcard send these to every client.");

		addConfigHeading(innerConfig, "Diagnostics");
		addConfigRow(innerConfig, "Debug Logging: ", debugLoggingBox,
				"Write registration and session details to the extension's output log.");

		JButton updateConfigButton = new JButton("Update Settings");
		updateConfigButton.addActionListener(e -> {
			String oldServer = burp.gui.Config.getHost();
			String oldPort = burp.gui.Config.getPort();
			String oldAuth = burp.gui.Config.getAuth();
			Boolean oldTls = burp.gui.Config.getScheme();
			int oldCidLength = burp.gui.Config.getCidLength();
			int oldCidNonceLength = burp.gui.Config.getCidNonceLength();

			String newServer = serverText.getText();
			String enteredPort = portText.getText();
			String newPort = Config.validPort(enteredPort, tlsBox.isSelected());
			portText.setText(newPort);
			if (!newPort.equals(enteredPort.trim())) {
				api.logging().logToError("Invalid port '" + enteredPort + "' - reset to " + newPort + ".");
			}
			String newAuth = authText.getText();
			Boolean newTls = tlsBox.isSelected();

			burp.gui.Config.updateConfig();
			cidLengthText.setText(String.valueOf(Config.getCidLength()));
			cidNonceLengthText.setText(String.valueOf(Config.getCidNonceLength()));
			pollField.setText(pollText.getText());
			applyRowFilter();
			updateUnreadCount();

			boolean criticalSettingChanged = !oldServer.equals(newServer)
					|| !oldPort.equals(newPort) || !oldAuth.equals(newAuth) || oldTls != newTls
					|| oldCidLength != Config.getCidLength() || oldCidNonceLength != Config.getCidNonceLength();

			if (criticalSettingChanged) {
				burp.BurpExtender.debugLog("Server configuration changed. Creating new Interact.sh session.");
				ToastNotification.showToast("Settings saved. Starting new session...", MessageType.INFO);
				this.listener.close();
				this.listener = new InteractshListener(
						newUrl -> ToastNotification.showToast("✓ Session ready.", MessageType.SUCCESS),
						errorMsg -> ToastNotification.showToast("❌ " + errorMsg, MessageType.ERROR));
			} else {
				ToastNotification.showToast("Settings saved.", MessageType.SUCCESS);
			}
		});
		JButton testConfigButton = new JButton("Test Settings");
		testConfigButton.setToolTipText("Try the values above against the server without saving them: registers a "
				+ "temporary session, checks that a test callback is recorded, then removes it.");
		testConfigButton.addActionListener(e -> {
			String host = serverText.getText().trim();
			boolean tls = tlsBox.isSelected();
			String enteredPort = portText.getText();
			String port = Config.validPort(enteredPort, tls);
			if (!port.equals(enteredPort.trim())) {
				ToastNotification.showToast("❌ Invalid port '" + enteredPort + "'.", MessageType.ERROR);
				return;
			}
			InteractshClient testClient = InteractshClient.forTest(host, Integer.parseInt(port), tls,
					authText.getText(), Config.validCidLength(cidLengthText.getText()),
					Config.validCidNonceLength(cidNonceLengthText.getText()), (String) aesModeBox.getSelectedItem());
			testConfigButton.setEnabled(false);
			ToastNotification.showToast("Testing settings...", MessageType.INFO);
			new Thread(() -> {
				String error = null;
				try {
					if (!testClient.register()) {
						error = (testClient.getLastError() != null) ? testClient.getLastError()
								: "Registration failed. See the extension's error log.";
					} else if (!testClient.verifyCallback()) {
						error = "Registered, but the server did not record a test callback. "
								+ "Check the correlation ID lengths and AES mode.";
					}
				} catch (RuntimeException ex) {
					error = "Test failed: " + ex.getMessage();
				} finally {
					if (testClient.isRegistered()) {
						testClient.deregister();
					}
				}
				String result = error;
				SwingUtilities.invokeLater(() -> {
					testConfigButton.setEnabled(true);
					if (result == null) {
						ToastNotification.showToast("✓ Settings work. Nothing was saved.", MessageType.SUCCESS);
					} else {
						ToastNotification.showToast("❌ " + result, MessageType.ERROR);
					}
				});
			}).start();
		});
		JPanel testButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		testButtonPanel.add(testConfigButton);
		innerConfig.add(updateConfigButton);
		innerConfig.add(testButtonPanel);

		SpringUtilities.makeCompactGrid(innerConfig, 17, 2, // rows, cols
				6, 6, // initX, initY
				6, 6); // xPad, yPad

		JPanel documentationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

		String documentationUrl = "https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#using-self-hosted-server";
		String linkHtml = "<html><b>View <a href=\"" + documentationUrl
				+ "\">the list of public Interactsh servers</a> on ProjectDiscovery's GitHub</b></html>";

		JEditorPane helpLink = createClickableLink(linkHtml);
		documentationPanel.setAlignmentY(Component.TOP_ALIGNMENT);
		documentationPanel.add(helpLink);
		configPanel.add(documentationPanel);

		add(mainPane);
	}

	private static void addConfigHeading(JPanel panel, String title) {
		JLabel heading = new JLabel(title, SwingConstants.LEADING);
		heading.setFont(heading.getFont().deriveFont(Font.BOLD));
		panel.add(heading);
		panel.add(new JPanel());
	}

	private static void addConfigRow(JPanel panel, String label, JComponent field, String toolTip) {
		JLabel rowLabel = new JLabel(label, SwingConstants.TRAILING);
		rowLabel.setToolTipText(toolTip);
		field.setToolTipText(toolTip);
		panel.add(rowLabel);
		panel.add(field);
	}

	public InteractshListener getListener() {
		return this.listener;
	}

	public static String getServerText() {
		return serverText.getText();
	}

	public static void setServerText(String t) {
		serverText.setText(t);
	}

	public static String getPortText() {
		return portText.getText();
	}

	public static void setPortText(String text) {
		portText.setText(text);
	}

	public static String getAuthText() {
		return authText.getText();
	}

	public static String getPollText() {
		return pollText.getText();
	}

	public static void setAuthText(String text) {
		authText.setText(text);
	}

	public static void setPollText(String text) {
		pollText.setText(text);
	}

	public static String getTlsBox() {
		return Boolean.toString(tlsBox.isSelected());
	}

	public static void setTlsBox(boolean value) {
		tlsBox.setSelected(value);
	}

	public static String getAesModeText() {
		return (String) aesModeBox.getSelectedItem();
	}

	public static void setAesModeText(String mode) {
		aesModeBox.setSelectedItem(mode);
	}

	public static String getDebugLogging() {
		return Boolean.toString(debugLoggingBox.isSelected());
	}

	public static void setDebugLogging(boolean value) {
		debugLoggingBox.setSelected(value);
	}

	public static String getCidLengthText() {
		return cidLengthText.getText();
	}

	public static void setCidLengthText(String text) {
		cidLengthText.setText(text);
	}

	public static String getCidNonceLengthText() {
		return cidNonceLengthText.getText();
	}

	public static void setCidNonceLengthText(String text) {
		cidNonceLengthText.setText(text);
	}

	public static String getHideWildcard() {
		return Boolean.toString(hideWildcardBox.isSelected());
	}

	public static void setHideWildcard(boolean value) {
		hideWildcardBox.setSelected(value);
	}

	public static String getHideShared() {
		return Boolean.toString(hideSharedBox.isSelected());
	}

	public static void setHideShared(boolean value) {
		hideSharedBox.setSelected(value);
	}

	private void applyRowFilter() {
		boolean hideShared = Config.isHideShared();
		boolean hideWildcard = Config.isHideWildcard();
		String protocol = selectedProtocol.toLowerCase();
		sorter.setRowFilter(new RowFilter<TableModel, Integer>() {
			@Override
			public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
				InteractshEntry ie = log.get(entry.getIdentifier());
				if ((hideShared && ie.isShared()) || (hideWildcard && ie.wildcard)) {
					return false;
				}
				return "all".equals(protocol) || ie.protocol.toLowerCase().contains(protocol);
			}
		});
	}

	private JEditorPane createClickableLink(String html) {
		JEditorPane editorPane = new JEditorPane("text/html", html);
		editorPane.setEditable(false);
		editorPane.setOpaque(false);
		editorPane.setHighlighter(null);

		editorPane.addHyperlinkListener(e -> {
			if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
				if (Desktop.isDesktopSupported()
						&& Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
					try {
						Desktop.getDesktop().browse(e.getURL().toURI());
					} catch (IOException | URISyntaxException ex) {
					}
				} else {
					String url = e.getURL().toString();
					StringSelection stringSelection = new StringSelection(url);
					try {
						Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
					} catch (Exception ex) {
						api.logging().logToError("Clipboard issue: " + ex.getMessage());
					}
					try {
						java.awt.datatransfer.Clipboard sel = Toolkit.getDefaultToolkit().getSystemSelection();
						if (sel != null)
							sel.setContents(stringSelection, null);
					} catch (Exception ex) {
					}
					api.logging().logToOutput(
							"Desktop browse is not supported. URL copied to clipboard: " + url);
				}
			}
		});
		return editorPane;
	}

	private void updateUnreadCount() {
		Container parent = getParent();
		if (parent instanceof JTabbedPane tabbedPane) {
			int tabIndex = tabbedPane.indexOfComponent(this);
			if (tabIndex != -1) {
				boolean hideShared = Config.isHideShared();
				boolean hideWildcard = Config.isHideWildcard();
				long unreadCount = log.stream().filter(e -> !e.isRead() && !(hideShared && e.isShared())
						&& !(hideWildcard && e.wildcard)).count();
				String newTitle = "Interactsh";
				if (unreadCount > 0) {
					newTitle += " (" + unreadCount + ")";
				}
				tabbedPane.setTitleAt(tabIndex, newTitle);
			}
		}
	}

	public void addToTable(InteractshEntry i) {
		SwingUtilities.invokeLater(() -> {
			synchronized (log) {
				log.add(i);
				int rowIndex = log.size() - 1;
				logTableModel.fireTableRowsInserted(rowIndex, rowIndex);
				updateUnreadCount();
			}
		});
	}

	private void clearLog() {
		synchronized (log) {
			log.clear();
			requestViewer.setRequest(null);
			responseViewer.setResponse(null);
			genericDetailsViewer.setText("");
			logTableModel.fireTableDataChanged();
			updateUnreadCount();
		}
	}

	private class Table extends JTable {

		public Table(TableModel tableModel) {
			super(tableModel);
		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend) {
			super.changeSelection(row, col, toggle, extend);

			int modelRow = convertRowIndexToModel(row);
			if (modelRow == -1) {
				return;
			}

			InteractshEntry selectedEntry = log.get(modelRow);

			if (!selectedEntry.isRead()) {
				selectedEntry.setRead(true);
				logTableModel.fireTableRowsUpdated(modelRow, modelRow);
				updateUnreadCount();
			}

			if (selectedEntry.protocol.equals("http") || selectedEntry.protocol.equals("https")) {
				resultsLayout.show(resultsCardPanel, "HTTP_VIEW");
				if (selectedEntry.httpRequest != null) {
					requestViewer.setRequest(selectedEntry.httpRequest);
					responseViewer.setResponse(selectedEntry.httpResponse);
				} else {
					resultsLayout.show(resultsCardPanel, "GENERIC_VIEW");
					genericDetailsViewer.setText(selectedEntry.details);
					genericDetailsViewer.setCaretPosition(0);
				}
			} else {
				resultsLayout.show(resultsCardPanel, "GENERIC_VIEW");
				genericDetailsViewer.setText(selectedEntry.details);
				genericDetailsViewer.setCaretPosition(0);
			}

			super.changeSelection(row, col, toggle, extend);
		}
	}

	private class LogTableCellRenderer extends DefaultTableCellRenderer {
		private static final DateTimeFormatter FORMATTER = DateTimeFormatter
				.ofPattern("yyyy-MM-dd HH:mm:ss.SSS z").withZone(ZoneId.systemDefault());

		private final Font plainFont;
		private final Font boldFont;

		public LogTableCellRenderer() {
			Font originalFont = getFont();
			this.plainFont = originalFont.deriveFont(Font.PLAIN);
			this.boldFont = originalFont.deriveFont(Font.BOLD);
			putClientProperty("html.disable", Boolean.TRUE);
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			final Component c = super.getTableCellRendererComponent(table, value, isSelected,
					hasFocus, row, column);

			if (value instanceof Instant) {
				setText(FORMATTER.format((Instant) value));
			} else {
				setText(value == null ? "" : value.toString());
			}

			if (!isSelected) {
				int modelRow = table.convertRowIndexToModel(row);
				InteractshEntry entry = log.get(modelRow);
				c.setFont(entry.isRead() ? plainFont : boldFont);
			}

			setHorizontalAlignment(SwingConstants.LEFT);

			return c;
		}
	}

	private class LogTable extends AbstractTableModel {
		public enum Column {
			ID("ID", Integer.class, 50, 80), ENTRY("Entry", String.class, 120, -1), TYPE("Type",
					String.class, 70, 100),
			SOURCE_IP("Source IP address", String.class, 120,
					-1),
			TIME("Time", Instant.class, 150, -1);

			@Getter
			private final String name;
			@Getter
			private final Class<?> type;
			@Getter
			private final int preferredWidth;
			@Getter
			private final int maxWidth;

			Column(String name, Class<?> type, int preferredWidth, int maxWidth) {
				this.name = name;
				this.type = type;
				this.preferredWidth = preferredWidth;
				this.maxWidth = maxWidth;
			}
		}

		@Override
		public int getRowCount() {
			return log.size();
		}

		@Override
		public int getColumnCount() {
			return Column.values().length;
		}

		@Override
		public String getColumnName(int columnIndex) {
			return Column.values()[columnIndex].getName();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return Column.values()[columnIndex].getType();
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			InteractshEntry ie = log.get(rowIndex);

			switch (Column.values()[columnIndex]) {
				case ID:
					return rowIndex + 1;
				case ENTRY:
					if (ie.wildcard) {
						return ie.uid + " (wildcard)";
					}
					return ie.isShared() ? "(shared)" : ie.uid;
				case TYPE:
					return ie.protocol;
				case SOURCE_IP:
					return ie.address;
				case TIME:
					return ie.timestamp;
				default:
					return "";
			}
		}
	}

	public void cleanup() {
		listener.closeAndWait();
	}
}
