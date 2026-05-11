package burp.gui;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import java.awt.Color;
import java.awt.Graphics;
import java.awt.Window;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.RoundRectangle2D;

public class ToastNotification extends JDialog {

    public enum MessageType {
        SUCCESS(new Color(34, 139, 34)),
        ERROR(new Color(178, 34, 34)),
        INFO(new Color(70, 130, 180));

        private final Color color;

        MessageType(Color color) {
            this.color = color;
        }

        public Color getColor() {
            return color;
        }
    }

    public static void showToast(String message, MessageType type) {
        SwingUtilities.invokeLater(() -> {
            if (burp.BurpExtender.api == null) return;
            Window owner = (Window) burp.BurpExtender.api.userInterface().swingUtils().suiteFrame();
            ToastNotification toast = new ToastNotification(owner, message, type);

            int x = owner.getX() + owner.getWidth() - toast.getWidth() - 20;
            int y = owner.getY() + owner.getHeight() - toast.getHeight() - 40;
            toast.setLocation(x, y);

            toast.setVisible(true);

            new Timer(4000, e -> {
                toast.setVisible(false);
                toast.dispose();
            }) {{
                setRepeats(false);
            }}.start();
        });
    }

    private ToastNotification(Window owner, String message, MessageType type) {
        super(owner);
        setUndecorated(true);
        setBackground(new Color(0, 0, 0, 0));

        JLabel label = new JLabel(message);
        label.setForeground(Color.WHITE);
        label.setBorder(new EmptyBorder(10, 15, 10, 15));

        setContentPane(new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(type.getColor());
                g2d.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 15, 15));
                g2d.dispose();
                super.paintComponent(g);
            }
        });

        ((JPanel) getContentPane()).setOpaque(false);
        add(label);
        pack();
    }
}
