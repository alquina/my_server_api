const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Tambahkan cors
require('dotenv').config();
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || '#Nsnsdeslemeng#1234567'; // Secret key untuk JWT


app.use(bodyParser.json());
app.use(express.json());
app.use(cors());



// Middleware untuk Verifikasi Token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Mendapatkan token dari header Authorization
  
    if (!token) return res.status(401).json({ message: 'Token is missing' });
  
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });
  
      req.user = user; // Menyimpan data user dari token ke dalam request
      next();
    });
  };


// Endpoint Registrasi
app.post('/api/register', (req, res) => {
  const { nama, email, username, password, role } = req.body;

  // Simpan password secara langsung tanpa hashing
  const query = `INSERT INTO user (nama, email, username, password, role) VALUES (?, ?, ?, ?, ?)`;
  const values = [nama, email, username, password, role || 'user'];

  db.query(query, values, (error, results) => {
    if (error) {
      console.error('Error registering user:', error.message);
      return res.status(500).json({ message: 'Database error during registration' });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
});


/// Endpoint Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Validasi input
  if (!username || !password) {
    return res.status(400).json({ message: 'Username dan password harus diisi.' });
  }

  // Cari user berdasarkan username
  db.query('SELECT * FROM user WHERE username = ?', [username], (error, results) => {
    if (error) {
      console.error('Database error:', error.message);
      return res.status(500).json({ message: 'Terjadi kesalahan pada server.' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Username atau password salah.' });
    }

    const user = results[0];

    // Cek password
    if (password !== user.password) {
      return res.status(401).json({ message: 'Username atau password salah.' });
    }

    // Buat JWT token
    const token = jwt.sign({ id: user.id_user, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

    // Kirim respons ke Flutter
    res.json({
      message: 'Login successful',
      token: token,
      role: user.role,
      user_id: user.id_user, // Kirim ID user untuk dipakai di Flutter
    });
  });
});


app.get('/api/user/:id_user', (req, res) => {
  const { id_user } = req.params; // Mengambil id_user dari URL parameter
  
  // Cek jika id_user ada
  if (!id_user) {
    return res.status(400).json({ error: 'ID pengguna tidak ditemukan.' });
  }

  // Query untuk mengambil data pengguna berdasarkan id_user
  db.query(
    'SELECT id_user, nama, email, username, role FROM user WHERE id_user = ?',
    [id_user],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Gagal mengambil data pengguna' });
      } 
      
      if (result.length > 0) {
        res.json(result[0]); // Mengembalikan data pengguna pertama (karena id_user unik)
      } else {
        res.status(404).json({ message: 'Pengguna tidak ditemukan' });
      }
    }
  );
});

app.put('/api/user/:id_user/change-password', (req, res) => {
  const { id_user } = req.params;
  const { current_password, new_password } = req.body;

  console.log('Endpoint dipanggil, ID User:', id_user);
  console.log('Data Body:', req.body);

  // Validasi input
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Password lama dan baru harus diisi.' });
  }

  // Query untuk mendapatkan password lama dari database
  db.query(
    'SELECT password FROM user WHERE id_user = ?',
    [id_user],
    (err, results) => {
      if (err) {
        console.error('Error saat mengambil password dari database:', err);
        return res.status(500).json({ error: 'Kesalahan server saat memproses permintaan.' });
      }

      if (results.length === 0) {
        console.log('User tidak ditemukan');
        return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
      }

      const storedPassword = results[0].password;
      console.log('Password dari Database:', storedPassword);

      // Bandingkan password lama secara langsung
      if (current_password !== storedPassword) {
        console.log('Password lama tidak cocok.');
        return res.status(400).json({ error: 'Password lama tidak cocok.' });
      }

      // Update password baru ke database
      db.query(
        'UPDATE user SET password = ? WHERE id_user = ?',
        [new_password, id_user],
        (err) => {
          if (err) {
            console.error('Error saat mengupdate password:', err);
            return res.status(500).json({ error: 'Kesalahan server saat memperbarui password.' });
          }

          console.log('Password berhasil diperbarui untuk user ID:', id_user);
          res.json({ message: 'Password berhasil diperbarui.' });
        }
      );
    }
  );
});

// Middleware untuk verifikasi token JWT
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'Token is required' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }

    req.user = decoded; // Menyimpan data user yang terautentikasi dalam request
    next();
  });
}

// Endpoint untuk Mengambil Data Pengaduan Berdasarkan User yang Login
app.get('/api/pengaduan/user/:userId', authenticateToken, (req, res) => {
  const { userId } = req.params;

  // Pastikan user hanya dapat melihat datanya sendiri
  if (req.user.id !== parseInt(userId)) {
    return res.status(403).json({ message: 'Unauthorized access' });
  }

  const query = `
    SELECT * FROM pengaduan 
    WHERE nama_pelapor IN (
      SELECT nama FROM user WHERE id_user = ?
    )
  `;

  db.query(query, [userId], (error, results) => {
    if (error) {
      console.error('Error fetching pengaduan:', error.message);
      return res.status(500).json({ message: 'Database error during pengaduan retrieval' });
    }

    res.json(results);
  });
});

// Endpoint untuk Mengambil Detail Pengaduan Berdasarkan ID
app.get('/api/pengaduan/:id_pengaduan', authenticateToken, (req, res) => {
  const { id_pengaduan } = req.params;

  const query = `
    SELECT * FROM pengaduan WHERE id_pengaduan = ?
  `;

  db.query(query, [id_pengaduan], (error, results) => {
    if (error) {
      console.error('Error fetching pengaduan detail:', error.message);
      return res.status(500).json({ message: 'Database error during pengaduan detail retrieval' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Pengaduan not found' });
    }

    res.json(results[0]);
  });
});

app.delete('/api/pengaduan/:idPengaduan', authenticateToken, (req, res) => {
  console.log('DELETE request received for:', req.params.idPengaduan);

  const { idPengaduan } = req.params;
  const query = 'DELETE FROM pengaduan WHERE id_pengaduan = ?';

  db.query(query, [idPengaduan], (error, results) => {
    if (error) {
      console.error('Database error:', error.message);
      return res.status(500).json({ message: 'Database error during deletion' });
    }

    if (results.affectedRows === 0) {
      console.log('No data found for the given ID.');
      return res.status(404).json({ message: 'Pengaduan not found' });
    }

    console.log('Data deleted successfully.');
    res.json({ message: 'Pengaduan deleted successfully' });
  });
});


// Endpoint: Mendapatkan Semua Data Pengaduan
app.get('/api/pengaduan', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM pengaduan';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error saat mengambil data pengaduan:', err);
      return res.status(500).json({ message: 'Gagal mengambil data pengaduan' });
    }
    res.json(results);
  });
});

// Endpoint: Mendapatkan Detail Pengaduan Berdasarkan ID
app.get('/api/pengaduan/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM pengaduan WHERE id_pengaduan = ?';
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Error saat mengambil detail pengaduan:', err);
      return res.status(500).json({ message: 'Gagal mengambil detail pengaduan' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Pengaduan tidak ditemukan' });
    }
    res.json(results[0]);
  });
});

// Endpoint: Update Status Pengaduan
app.put('/api/pengaduan/:id/status', authenticateToken, (req, res) => {
  const { id } = req.params; // ID pengaduan yang akan diupdate
  const { status } = req.body; // Status baru yang dikirim oleh client

  // Validasi input status
  const validStatuses = ['diproses', 'diterima', 'ditolak'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Status tidak valid' });
  }

  const sql = 'UPDATE pengaduan SET status = ? WHERE id_pengaduan = ?';
  db.query(sql, [status, id], (err, result) => {
    if (err) {
      console.error('Error saat mengupdate status pengaduan:', err);
      return res.status(500).json({ message: 'Gagal mengupdate status pengaduan' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Pengaduan tidak ditemukan' });
    }

    res.json({ message: 'Status pengaduan berhasil diperbarui' });
  });
});

// Endpoint Pengaduan
app.post('/api/pengaduan', authenticateToken, (req, res) => {
  const {
    nama_pelapor, tempat_lahir_pelapor, tggl_lahir_pelapor, jenis_kelamin_pelapor, nim_nip_pelapor, nomor_tlp_pelapor,
    nama_korban, tempat_lahir_korban, tggl_lahir_korban, jenis_kelamin_korban, nim_nip_korban, nomor_tlp_korban,
    unit_kerja_korban, tempat_kejadian, nama_pelaku, unit_kerja_pelaku, jenis_kekerasan, layanan, kronologi,
    bukti_file_path, saksi, status
  } = req.body;

  const query = `
    INSERT INTO pengaduan (
      nama_pelapor, tempat_lahir_pelapor, tggl_lahir_pelapor, jenis_kelamin_pelapor, nim_nip_pelapor, nomor_tlp_pelapor,
      nama_korban, tempat_lahir_korban, tggl_lahir_korban, jenis_kelamin_korban, nim_nip_korban, nomor_tlp_korban,
      unit_kerja_korban, tempat_kejadian, nama_pelaku, unit_kerja_pelaku, jenis_kekerasan, layanan, kronologi,
      bukti_file_path, saksi, status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const values = [
    nama_pelapor, tempat_lahir_pelapor, tggl_lahir_pelapor, jenis_kelamin_pelapor, nim_nip_pelapor, nomor_tlp_pelapor,
    nama_korban, tempat_lahir_korban, tggl_lahir_korban, jenis_kelamin_korban, nim_nip_korban, nomor_tlp_korban,
    unit_kerja_korban, tempat_kejadian, nama_pelaku, unit_kerja_pelaku, jenis_kekerasan, layanan, kronologi,
    bukti_file_path, saksi, status || 'diproses'  // Status default ke 'diproses'
  ];

  db.query(query, values, (error, results) => {
    if (error) {
      console.error('Error inserting pengaduan:', error.message);
      return res.status(500).json({ message: 'Database error during pengaduan submission' });
    }
    res.json({ message: 'Pengaduan submitted successfully' });
  });
});

// Menjalankan Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
