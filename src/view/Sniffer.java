package view;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Vector;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import capture.Analyse;
import capture.Captor;
import jpcap.packet.Packet;

public class Sniffer extends JFrame {
	private JTable table;
	private JTree tree;
	private JTextArea textArea;
	private JComboBox<String> comboBox;
	private JComboBox<String> protocolComboBox;

	private boolean isCapturing = true;
	private boolean isSelectionEnabled = true;

	private List<Packet> packets;
	private List<Packet> result = new ArrayList<>();
	private Captor captor = new Captor();
	private int selectionCount = 0;

	private JButton exportButton;

	public Sniffer() {
		initializeUI();
	}

	private void initializeUI() {
		setTitle("网络嗅探器");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(400, 200, 800, 500); // 调整主窗口大小
		getContentPane().setLayout(null);

		// Initialize table
		initializeTable();

		// Network interface selection
		initializeDeviceComboBox();

		// Filter protocol dropdown
		initializeProtocolComboBox();

		// Initialize buttons
		initializeButtons();

		// Text area for packet info
		initializeTextArea();

		// Information tree
		initializeTree();

		// Clear button
		initializeClearButton();

		// Save a line of info
		initializeExportButton();
	}

	private void initializeExportButton() {
		exportButton = new JButton("导出");
		exportButton.setEnabled(false); // 初始状态为不可点击
		exportButton.setBounds(670, 11, 80, 25);
		exportButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				exportSelectedPackets();
			}
		});
		getContentPane().add(exportButton);
	}

	private void exportSelectedPackets() {
		// 选择文件对话框，让用户选择保存路径
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("选择导出文件保存路径");

		int userSelection = fileChooser.showSaveDialog(this);

		if (userSelection == JFileChooser.APPROVE_OPTION) {
			java.io.File fileToSave = fileChooser.getSelectedFile();
			saveSelectedPacketToFile(fileToSave);
		}
	}

	private void saveSelectedPacketToFile(java.io.File file) {
		try {
			// 创建文件输出流
			java.io.FileWriter writer = new java.io.FileWriter(file);

			// 获取选中行的索引
			int selectedIndex = table.getSelectedRow();
			if (selectedIndex >= 0 && selectedIndex < result.size()) {
				Packet selectedPacket = result.get(selectedIndex);

				// 获取数据包的详细信息
				String packetInfo = captor.showPacket(selectedPacket);

				// 写入文件
				writer.write(packetInfo);
				writer.flush();
				writer.close();

				// 显示提示信息
				javax.swing.JOptionPane.showMessageDialog(this, "导出成功!", "导出", javax.swing.JOptionPane.INFORMATION_MESSAGE);
			} else {
				javax.swing.JOptionPane.showMessageDialog(this, "没有选中任何数据包!", "错误", javax.swing.JOptionPane.ERROR_MESSAGE);
			}
		} catch (Exception e) {
			e.printStackTrace();
			javax.swing.JOptionPane.showMessageDialog(this, "导出失败: " + e.getMessage(), "错误", javax.swing.JOptionPane.ERROR_MESSAGE);
		}
	}

	private void initializeTable() {
		Vector<String> columnNames = new Vector<>();
		columnNames.add("编号"); // ID
		columnNames.add("时间"); // Time
		columnNames.add("长度"); // Length
		columnNames.add("源IP地址"); // Source IP Address
		columnNames.add("目的IP地址"); // Destination IP Address
		columnNames.add("协议"); // Protocol
		columnNames.add("源MAC地址"); // Source MAC Address
		columnNames.add("目的MAC地址"); // Destination MAC Address

		DefaultTableModel model = new DefaultTableModel(columnNames, 0) {
			private static final long serialVersionUID = 1L;

			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};

		table = new JTable(model);
		table.setBounds(22, 42, 730, 160);
		JScrollPane scrollPane = new JScrollPane(table);
		scrollPane.setBounds(22, 42, 730, 160);
		getContentPane().add(scrollPane);

		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				selectionCount++;
				handleTableSelection();
			}
		});
	}

	private void initializeDeviceComboBox() {
		String[] deviceList = captor.showDevice();
		comboBox = new JComboBox<>(deviceList);
		comboBox.setBounds(22, 11, 240, 25);
		getContentPane().add(comboBox);
	}

	private void initializeProtocolComboBox() {
		String[] protocols = { "All", "TCP", "UDP", "ARP", "IPv4", "IPv6", "Ethernet", "HTTP", "Others" };
		protocolComboBox = new JComboBox<>(protocols);
		protocolComboBox.setBounds(285, 11, 90, 25);
		getContentPane().add(protocolComboBox);
	}

	private void initializeButtons() {
		JButton startButton = new JButton("开始");
		startButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				startCapture();
			}
		});
		startButton.setBounds(400, 11, 80, 25);
		getContentPane().add(startButton);

		JButton cancelButton = new JButton("停止");
		cancelButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCapture();
			}
		});
		cancelButton.setBounds(490, 11, 80, 25);
		getContentPane().add(cancelButton);
	}

	private void initializeTextArea() {
		textArea = new JTextArea();
		textArea.setBounds(220, 220, 530, 220);
		textArea.setEditable(false);
		JScrollPane scrollPane = new JScrollPane(textArea);
		scrollPane.setBounds(220, 220, 530, 220);
		getContentPane().add(scrollPane);
	}

	private void initializeTree() {
		tree = new JTree();
		tree.setBounds(22, 220, 180, 220);
		JScrollPane scrollPane = new JScrollPane(tree);
		scrollPane.setBounds(22, 220, 180, 220); // 调整滚动条的大小
		getContentPane().add(scrollPane);
	}

	private void initializeClearButton() {
		JButton clearButton = new JButton("清空");
		clearButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				clearData();
			}
		});
		clearButton.setBounds(580, 11, 80, 25);
		getContentPane().add(clearButton);
	}

	private void handleTableSelection() {
		new Thread(new Runnable() {
			@Override
			public void run() {
				EventQueue.invokeLater(new Runnable() {
					@Override
					public void run() {
						int index = table.getSelectedRow();
						if (index >= 0 && index < result.size()) {
							// 如果有选中的数据包，启用导出按钮
							exportButton.setEnabled(true);
						} else {
							// 如果没有选中的数据包，禁用导出按钮
							exportButton.setEnabled(false);
						}

						if (isSelectionEnabled) {
							Packet packet = result.get(index);
							Analyse analyse = new Analyse();
							analyse.startClassify(packet);
							LinkedHashMap<String, ArrayList<String>> info = analyse.getInfo();

							DefaultMutableTreeNode top = new DefaultMutableTreeNode("第" + (index + 1) + "个数据包");
							for (Iterator<Entry<String, ArrayList<String>>> it = info.entrySet().iterator(); it.hasNext();) {
								Entry<String, ArrayList<String>> entry = it.next();
								ArrayList<String> arrayList = entry.getValue();
								top.add(new DefaultMutableTreeNode(entry.getKey() + ":"));
								for (String s : arrayList) {
									top.add(new DefaultMutableTreeNode(s));
								}
							}

							DefaultTreeModel treeModel = new DefaultTreeModel(top);
							tree.setModel(treeModel);
							textArea.setText(captor.showPacket(packet));
						}
					}
				});
			}
		}).start();
	}

	private void startCapture() {
		isSelectionEnabled = true;
		isCapturing = true;

		String chosenDevice = (String) comboBox.getSelectedItem();
		chooseDeviceByName(chosenDevice);

		String protocol = (String) protocolComboBox.getSelectedItem();
		captor.capturePackets();
		Analyse analyse = new Analyse();

		new Thread(new Runnable() {
			@Override
			public void run() {
				String selectedDevice = (String) comboBox.getSelectedItem();
				chooseDeviceByName(selectedDevice);

				String filterProtocol = (String) protocolComboBox.getSelectedItem();
				captor.capturePackets();
				Analyse packetAnalyse = new Analyse();

				int count = 0;
				int num = 0;

				while (isCapturing) {
					packets = captor.getPackets();
					if (packets.size() > count) {
						Packet packet = packets.get(count++);
						String[] info = packetAnalyse.getInfo(packet);

						// Apply protocol filter
						if (filterProtocol.equals("All") || filterProtocol.equals(info[4])) {
							result.add(packet);
							num++;

							Vector<Object> row = new Vector<>();
							row.add(num);
							row.add(info[0]); // Time
							row.add(info[1]); // Length
							row.add(info[5]); // Source IP Address
							row.add(info[6]); // Destination IP Address
							row.add(info[4]); // Protocol
							row.add(info[2]); // Source MAC Address
							row.add(info[3]); // Destination MAC Address

							// Update the table
							EventQueue.invokeLater(new Runnable() {
								@Override
								public void run() {
									((DefaultTableModel) table.getModel()).addRow(row);
								}
							});
						}
					}
				}
			}
		}).start();
	}

	private void stopCapture() {
		isCapturing = false;
		captor.stopCaptureThread();
	}

	private void clearData() {
		if (packets != null) {
			packets.clear();
		}
		result.clear();
		isCapturing = false;
		isSelectionEnabled = false;
		textArea.setText(null);

		// 清空树
		tree.setModel(new DefaultTreeModel(null));

		// 清空表格
		DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
		tableModel.setRowCount(0);
	}

	private void chooseDeviceByName(String deviceName) {
		String[] deviceList = captor.showDevice();
		for (int i = 0; i < deviceList.length; i++) {
			if (deviceList[i].equals(deviceName)) {
				captor.chooseDevice(i);
				break;
			}
		}
	}

	public static void main(String[] args) {
		EventQueue.invokeLater(() -> {
			new Sniffer().setVisible(true);
		});
	}
}
