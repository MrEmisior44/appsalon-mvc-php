<?php

namespace Model;

class AdminCita extends ActiveRecord {
    protected static $tabla = 'citasServicios';
    protected static $columnasDB = ['id', 'fecha', 'hora', 'cliente', 'email', 'telefono', 'servicio', 'precio'];

    public $id;
    public $fecha;
    public $hora;
    public $cliente;
    public $email;
    public $telefono;
    public $servicio;
    public $precio;

    function __construct($args = [])
    {
        $this->id = $args = ['id'] ?? null;
        $this->fecha = $args = ['fecha'] ?? '';
        $this->hora = $args = ['hora'] ?? '';
        $this->cliente = $args = ['cliente'] ?? '';
        $this->email = $args = ['email'] ?? '';
        $this->telefono = $args = ['telefono'] ?? '';
        $this->servicio = $args = ['servicio'] ?? '';
        $this->precio = $args = ['precio'] ?? '';
    }

    
}


?>