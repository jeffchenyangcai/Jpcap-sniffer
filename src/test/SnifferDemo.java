package test;

import javax.swing.*;
import jpcap.*;
import jpcap.packet.Packet;
import java.util.ArrayList;

public class SnifferDemo {
    public static void main(String[] args) throws Exception {
        // 获取网卡列表
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();

        // 创建一个简单的窗口
        JFrame frame = new JFrame("网络嗅探器");
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // 显示网卡列表
        JComboBox<String> deviceBox = new JComboBox<>();
        for (NetworkInterface device : devices) {
            deviceBox.addItem(device.name);
        }

        JButton startButton = new JButton("开始捕获");
        JTextArea textArea = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(textArea);

        startButton.addActionListener(e -> {
            int selectedIndex = deviceBox.getSelectedIndex();
            new Thread(() -> {
                try {
                    // 选择指定网卡开始捕获数据包
                    JpcapCaptor captor = JpcapCaptor.openDevice(devices[selectedIndex], 65535, false, 20);
                    while (true) {
                        Packet packet = captor.getPacket();
                        if (packet != null) {
                            textArea.append(packet.toString() + "\n");
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }).start();
        });

        JPanel panel = new JPanel();
        panel.add(deviceBox);
        panel.add(startButton);

        frame.add(panel, "North");
        frame.add(scrollPane, "Center");
        frame.setVisible(true);
    }
}