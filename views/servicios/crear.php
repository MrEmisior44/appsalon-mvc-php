<h1 class="nombre-pagina">Nuevo Servicio</h1>
<p class="descripcion-pagina">Crea un nuevo servicio rellenando el formulario</p>

<?php
    include_once __DIR__ . '/../templates/barra.php';
    include_once __DIR__ . '/../templates/alertas.php';
?>

<form class="formulario" action="/servicios/crear" method="POST">
    <?php include_once __DIR__ . '/formulario.php'; ?>
    <input class="boton" type="submit" value="Guardar Servicio">
</form>